/*
 * traffic_gen.c
 *
 *  Created on: Mar 1, 2017
 *      Author: dkutergin
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <argp.h>
#define TOLERANCE_HI 25
#define TOLERANCE_LOW 3
#define SDV_TARGET 2
#define RATE_SCALE 100

struct opts_t {
	uint8_t verbosity;
	uint64_t tx_rate_set;
	float sdv_target;
};
//Version
const char *argp_program_version =
  "traffic_gen.1.0";

// Program documentation.
static char doc[] =
  "Traffic generator -- generate traffic using pattern [XXXXX;] for X = 0..65536";
// Supported opts
static struct argp_option cmd_options[] = {
  {"verbose", 'v', "level",     0, "Produce verbose output. Levels 0 - no output, 1 - statistics, 2 -full debug" },
  {"rate",	  'r', "rate",      0, "Required traffic generation rate Bytes/s" },
  {"sdv",     's', "deviation",	0, "Standard deviation target value in percents"},
  { 0 }
};

// Options parser
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our opts structure. */
  struct opts_t *opts = (struct opts_t *)state->input;
  static uint8_t rate_got = 0;
  switch (key){
    case 'v':
      opts->verbosity = arg ? atoi(arg): 1;
      break;
    case 'r':
      rate_got = 1;
      if(arg)
    	  opts->tx_rate_set = strtoul(arg, NULL, 10);
      else
    	  argp_usage (state);
      break;
    case 's':
      if(arg)
    	  opts->sdv_target = strtof(arg, NULL);
      else
    	  argp_usage (state);
      break;
    case ARGP_KEY_END:
    	if(!rate_got)
    		argp_usage (state);
    	return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}
static struct argp argp = { cmd_options, parse_opt, NULL, doc };
int main(int argc, char *argv[])
{
	static char tr_buff[0xffff][7];
	struct opts_t run_opts ={0, 0, SDV_TARGET};

	argp_parse (&argp, argc, argv, 0, 0, &run_opts);

	uint64_t tx_rate = run_opts.tx_rate_set; //bytes/sec
	uint64_t result_rate;
	uint64_t result_rate_low = -1;
	uint64_t result_rate_hi = 0;
	uint64_t sum_rate = 0;
	uint64_t mean_rate = 0;
	uint64_t sample_count = 0;
	uint64_t sum_dv = 0;
	uint64_t nsec_delay_sum = 0;
	uint64_t nsec_delay_mean = 0;
	struct timespec ts_before;
	struct timespec ts_after;
	struct timespec sleep_time;
	//disabling stdout buffering
	setvbuf(stdout, NULL, _IONBF, 0);
	uint32_t i = 0;
	for(; i <= 0xffff; ++i){
		snprintf(tr_buff[i], sizeof(tr_buff[i]), "%.5d;", i);
	}
	i = 0;
	uint32_t tr_size = 1;
	uint32_t prev_tr_size = 0;
	uint64_t byte_count = 0;
	int64_t nsec_leftover = 0;
	int64_t nsec_elapsed_final = 0;
	int64_t nsec_needed = 0;
	uint32_t step_down = 1;
	uint32_t step_up = 1;
	while(1){

		clock_gettime(CLOCK_MONOTONIC, &ts_before);
		uint32_t tr_size_bytes = tr_size * sizeof(tr_buff[i]) -1;
#ifdef DEBUG_BUF_EN
		snprintf(tr_buff[i], sizeof(tr_buff[i]), "%.5d|", tr_size);
		if(tr_size > 10)
			printf("tr_size = %d\n", tr_size);
#endif
		write(STDOUT_FILENO, tr_buff[i], tr_size_bytes);
		clock_gettime(CLOCK_MONOTONIC, &ts_after);
		i += tr_size;
		int64_t nsec_elapsed = ((ts_after.tv_sec * 1e9
		                + ts_after.tv_nsec) - (ts_before.tv_sec * 1e9 + ts_before.tv_nsec));
		uint64_t computed_rate = 1 + (tr_size_bytes * 1e9) / nsec_elapsed;
		int64_t nsec_theor = ((tr_size_bytes * 1e9) / tx_rate);
		int64_t nsec_delay_diff = nsec_theor - nsec_elapsed;
		nsec_needed = nsec_delay_diff;


		if(nsec_needed < 0) {
			nsec_needed = 0;
			tr_size += step_up++;
			step_down = 1;
		} else if (nsec_needed < 2000) {
			tr_size += step_up++;
			step_down = 1;
		} else {
			byte_count += tr_size_bytes;
			if(++byte_count > run_opts.tx_rate_set / 2) {
				step_up = 1;
				if(run_opts.verbosity > 1) {
					fprintf(stderr, "Before: step_down=%d, step_up=%d, sdv_target %.2f\n", step_down, step_up, run_opts.sdv_target);
				}
				if(tr_size > step_down) {
					tr_size -= step_down++;
//					step_down++;
				} else {
					step_down = 1;
				}
				if ((100 * sqrt(sum_dv / sample_count) / (float)mean_rate) > run_opts.sdv_target){
					step_down = 1;
					tr_size += step_up++;
				}
				byte_count = 0;
				if(run_opts.verbosity > 0) {
					fprintf(stderr, "Transmission size: %d, mean delay: %lu ns, result rate: min=%lu B/s, max=%lu B/s, mean=%lu B/s, sdv=%.2f B/s, accuracy=%.2f%% \n",
						tr_size, nsec_delay_mean, result_rate_low, result_rate_hi, mean_rate, sqrt(sum_dv / sample_count), 100 * sqrt(sum_dv / sample_count) / (float)mean_rate);
				}
				result_rate_low = -1;
				result_rate_hi = 0;

				sum_rate = 0;
				sum_dv = 0;

				nsec_delay_mean = nsec_delay_sum / sample_count;
				nsec_delay_sum = 0;
				sample_count = 0;
				if(run_opts.verbosity > 1) {
					fprintf(stderr, "After: step_down=%d, step_up=%d, sdv_target %.2f\n", step_down, step_up, run_opts.sdv_target);
				}
			}

		}

		if (nsec_needed > 100000) {
			if(run_opts.verbosity > 1)
				printf("Sleep for %ld ns\n", nsec_needed);
			sleep_time.tv_sec = nsec_needed / 1e9;
			sleep_time.tv_nsec = (int)nsec_needed % (int)1e9;
			nanosleep(&sleep_time, NULL);
		} else if (nsec_needed > 1000) {
			uint64_t nsec_target = (ts_after.tv_sec * 1e9 + ts_after.tv_nsec) + nsec_needed;
			uint64_t nsec_curr;
			if(run_opts.verbosity > 1)
				fprintf(stderr, "Wait for %ld ns, target= %lu ns\n", nsec_needed, nsec_target);
			do {
				clock_gettime(CLOCK_MONOTONIC, &sleep_time);
				nsec_curr = sleep_time.tv_sec * 1e9 + sleep_time.tv_nsec;
			}while (nsec_curr < nsec_target);
		}

		if (tr_size < 1)
			tr_size = 1;

		if (tr_size > 0xffff)
			tr_size = 0xffff;

		if (i >= 0xffff)
			i = 0;

		clock_gettime(CLOCK_MONOTONIC, &ts_after);
		nsec_elapsed_final = ((ts_after.tv_sec * 1e9
						+ ts_after.tv_nsec) - (ts_before.tv_sec * 1e9 + ts_before.tv_nsec));
		result_rate = (tr_size_bytes * 1e9) / (nsec_elapsed_final + nsec_delay_mean);
		if(result_rate * RATE_SCALE > (run_opts.tx_rate_set * (RATE_SCALE + TOLERANCE_LOW)))
			tx_rate -= (tx_rate * TOLERANCE_LOW) / RATE_SCALE;
		else if (result_rate * RATE_SCALE < (run_opts.tx_rate_set * (RATE_SCALE - TOLERANCE_LOW)))
			tx_rate += (tx_rate * TOLERANCE_LOW) / RATE_SCALE;
		if (result_rate > result_rate_hi)
			result_rate_hi = result_rate;
		if (result_rate < result_rate_low)
			result_rate_low = result_rate;

		sum_rate += result_rate;
		sample_count++;
		mean_rate = sum_rate / sample_count;
		sum_dv += ((int64_t)result_rate - (int64_t)mean_rate) * ((int64_t)result_rate - (int64_t)mean_rate);

		clock_gettime(CLOCK_MONOTONIC, &sleep_time);
		uint64_t nsec_delay = ((sleep_time.tv_sec * 1e9
				                + sleep_time.tv_nsec) - (ts_after.tv_sec * 1e9 + ts_after.tv_nsec));
		nsec_delay_sum += nsec_delay;
		if(run_opts.verbosity > 1) {
			fprintf(stderr, ":tr_size=%d, prev_tr_size=%d, nsec_needed=%ld ns, nsec_elapsed= %ld ns, nsec_delay=%ld ns, nsec_final=%ld ns, nsec_theor=%ld ns, nsec_leftover=%ld ns\ncomputed_rate=%lu Bytes/s, result_rate=%lu Bytes/s, tx_rate=%lu\n",
				tr_size, prev_tr_size, nsec_needed, nsec_elapsed, nsec_delay, nsec_elapsed_final, nsec_theor, nsec_leftover,
				computed_rate, result_rate, tx_rate);
		}
	}
	return 0;
}
