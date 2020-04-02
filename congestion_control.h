#ifndef _CCONTROL_H_
#define _CCONTROL_H_

#include "bitset.h"
#include "hercules.h"

#define RCTS_INTERVALS 4 // Must be even

// PCC state machine states
enum pcc_state{pcc_startup, pcc_decision, pcc_adjust};

struct rct {
	u32 rate;
	float utility;
};

// RCTs result
enum rcts_result{increase, decrease, inconclusive};

struct ccontrol_state {
	// Cons
	u32 max_rate_limit; // Max sending rate that the CC algorithm should not exceed
	double pcc_mi_duration;
	double rtt; // Round-trip time in seconds

	// Monitoring interval values
	u32 ack_start;
	u32 ack_end;
	struct bitset mi_acked_chunks;

	u32 prev_rate;
	u32 curr_rate;
	float prev_utility;
	float eps;
	float sign;
	int adjust_iter;
	unsigned long mi_start;

	struct rct rcts[RCTS_INTERVALS];
	int rcts_iter;
	enum pcc_state state;
};


/*!
 * @function	init_ccontrol_state
 * @abstract	Initialize the congestion control state and return it.
 * @param	rtt		u64, Round-trip time in nanoseconds
 * @param	total_chunks	the total number of chunks, needed for the rolling ACK accounting
 * @result	A ccontrol_state struct
*/
// Initialize congestion control state
struct ccontrol_state *init_ccontrol_state(u32 max_rate_limit, u64 rtt, u32 total_chunks);

// Apply PCC control decision, return new rate
u32 pcc_control(struct ccontrol_state *cc_state, float throughput, float loss);

#endif
