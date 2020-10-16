# Hercules

High speed bulk data transfer application.

This is a proof of concept implementation of file transfer using SCION/UDP (over ethernet/IPv4/UDP).
To achieve high transmit and receive rates, the `hercules` tool is implemented using `AF_XDP`.
On suitable hardware, a single instance can achieve >98Gbps transfer rate, and multiple instances can run in parallel on different network interfaces.

`hercules` is not a daemon, it performs for only a single file transmission and then stops. 
There are at least two hosts involved; exactly one of which behaves as a _sender_, the remaining hosts behave as receiver.
The sender transmits the data to all receivers.
Each receiver waits for the sender to start the transmission.
There is no authorization, access control etc. The idea is that this will be integrated in a more generic framework that does all of that (e.g. make this run as an FTP extension).

## Building

Option
1. Build in Docker, using the `Dockerfile` and `Makefile` provided in the repo; just run `make`.

1. Build using `go build`
  
   Requires:
    - gcc/clang
    - linux kernel headers >= 5.0
    - go >= 1.15


## Running

> **WARNING**: network drivers seem to crash occasionally.

> **WARNING**: due to the most recent changes on the branch `multicore`, the rate-limit `computation` is a bit off.
  When setting the rate-limit with `-p`, keep this in mind and set a lower rate than you aim at.

> **NOTE**: if hercules is aborted forcefully (e.g. while debugging), it can leave an XDP program loaded which will prevent starting again.
						Run `ip link set dev <device> xdp off`.

> **NOTE**: many things can go wrong, expect to diagnose things before getting it to work.

> **NOTE**: Some devices use separate queues for copy and zero-copy mode (e.g. Mellanox).
  Make sure to use queues that support the selected mode.
  Additionally, you may need to postpone step 2 until the handshake has succeeded.

1. Make sure that SCION endhost services (sciond, dispatcher) are configured and running on both sender and receiver machines.
   For the most recent versions of Hercules, use a SCION version compatible to `v2020.03-scionlab`.

1. Configure queue network interfaces to particular queue (if supported by device); in this example queue 0 is used. 

    ```shell
    sudo ethtool -N <device> rx-flow-hash udp4 fn
    sudo ethtool -N <device> flow-type udp4 dst-port 30041 action 0
    ```

1. Start hercules on receiver side

    ```shell
    sudo numactl -l --cpunodebind=netdev:<device> -- \ 
        ./hercules -i <device> -q 0 -l <receiver addr> -o path/to/output/file.bin
    ```

1. Start hercules on sender side

    ```shell
    sudo numactl -l --cpunodebind=netdev:<device> -- \
        ./hercules -i <device> -q 0 -l <sender addr> -d <receiver addr> -t path/to/file.bin
    ```

* Both `<receiver addr>` and `<sender addr>` are SCION/IPv4 addresses with UDP port, e.g. `17-ffaa:0:1102,[172.16.0.1]:10000`.
* To send data to multiple receivers, just provide `-d` multiple times.
* The `numactl` is optional but has a huge effect on performance on systems with multiple numa nodes.
* The command above will use PCC for congestion control. For benchmarking, you might want to use `-pcc=false` and provide a maximum sending rate using `-p`.
* For transfer rates >30Gbps, you might need to use multiple networking queues. At the receiver this is currently only possible in combination with multiple IP addresses. 
* See source code (or `-h`) for additional options.
* You should be able to omit `-l`.
* For more sophisticated run configurations (e.g. using multiple paths), it is recommended to use a configuration file.
* When using 4 or more paths per destination, you might need to specify path preferences to make the path selection more efficient. 


## Protocol

The transmitter splits the file into chunks of the same size. All the chunks are transmitted (in order).
The receiver acknowledges the chunks at regular intervals.
Once the sender has transmitted all chunks once, it will start to retransmit all chunks that have not been acknowledge in time. 
This is repeated until all chunks are acked.


---


All packets have the following basic layout:

	|  index  |  path  | payload ... |
	|   u32   |   u8   |     ...     |


> **NOTE**: Integers are transmitted little endian (host endianness).

For control packets (handshake and acknowledgements, either sender to receiver or receiver to sender), index is `UINT_MAX`.
For all control packets, the first byte of the payload contains the control packet type.
The following control packet types exist:

    0: Handshake packet
    1: ACK packet
    2: PCC feedback packet

For data packets (sender to receiver), the index field is the index of the chunk being transmitted. This is **not** a packet sequence number, as chunks may be retransmitted.

If path is not `UINT8_MAX`, it is used to account the packet to a specific path.
This is used to provide quick feedback to the PCC algorithm, if enabled.


#### Handshake

1. Sender sends initial packet:

        | num entries | filesize | chunksize | timestamp | path index | flags |
        |     u8      |   u64    |   u32     |    u64    |    u32     |  u8   |
        
    Where `num entries` is `UINT8_MAX` to distinguish handshake replies from ACKs.
    
    Flags:
    - 0-th bit: `SET_RETURN_PATH` The receiver should use this path for sending
    ACKs from now on.

1. Receiver replies immediately with the same packet.

    This first packet is used to determine an approximate round trip time.
    
	The receiver proceeds to  prepare the file mapping etc.

1. Receiver replies with an empty ACK signaling "Clear to send"

##### Path handshakes

Every time the sender starts using a new path or the receiver starts using a new
return path, the sender will update the RTT estimate used by PCC.
In order to achieve this, it sends a handshake (identical to the above) on the
affected path(s).
The receiver replies immediately with the same packet (using the current return path).

#### Data transmit

* The sender sends (un-acknowledged) chunks in data packets at chosen send rate
* The receiver sends ACK packets for the entire file at 100ms intervals.
    
  ACK packets consist of a list of `begin`,`end` pairs declaring that chunks
  with index `i` in `begin <= i < end` have been received.
  Lists longer than the packet payload size are transmitted as multiple 
  independent packets with identical structure.


        | begin, end | begin, end | begin, end | ...
        |  u32   u32 |  u32   u32 |  u32   u32 | ...

* The receiver sends a PCC feedback two times per RTT.
  The PCC feedback packet uses the following payload layout:
   
        | num paths | pkt count | pkt count | ...
        |    u8     |    u32    |    u32    | ...
       
  These PCC feedback packets are not sent, if no paths have been accounted packets for
  (e.g. if no path uses PCC). 

#### Termination

1. Once the receiver has received all chunks, it sends one more ACK for the entire range and terminates.
1. When the sender receives this last ACK, it determines that all chunks have been received and terminates.

## Issues, Todos, Future Work

* [ ] Flow control: if the receiver is slower than the sender (e.g. because it needs to write stuff to disk) it just drops packets.
	  The congestion control naturally solves this too, but is fairly slow to adapt.
	  Maybe a simple window size would work.
* [ ] Abort of transmission not handled (if one side is stopped, the other side will wait forever).
* [ ] Replace paths used for sending before they expire (for very long transmissions)
* [ ] Optimisations; check sum computations, file write (would be broken for huge files), ...
