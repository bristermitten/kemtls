/* Note to implementors:
   Make sure sizeof(struct packet) <= sizeof(struct pacing_packet).
   Make sure sizeof(struct connection) <= sizeof(struct pacing_connection).
*/

#include "pacing.h"
#include <stdlib.h>
#include <time.h>

#define MINCWND 8192
#define INITCWND 24576

struct windowedmax_sample {
  double t;
  double v;
} ;

struct windowedmax {
  struct windowedmax_sample s[3];
} ;

struct packet {
  int transmissions;
  int acknowledged;
  long long len;
  double transmissiontime; /* most recent */
  long long save_netbytesdelivered;
  double save_netbytesdelivered_time;
  double first_sent_time;
} ;

struct connection {
  double now;
  double lastsending; /* time of most recent transmission or retransmission */
  long long bytesinflight; /* packets transmitted and not yet acknowledged */
  long long packetssent;
  long long packetsreceived;

  /* at pacing_when, would have been comfortable sending pacing_netbytes */
  double pacing_when;
  long long pacing_netbytes;

  /* setting retransmission timeout: */

  int rtt_measured; /* 1 if pacing_newrtt() has ever been called */
  double rtt_smoothed; /* "srtt"; smoothing of rtt measurements */
  double rtt_variance; /* "rttvar"; estimate of rtt variance */
  double rtt_nextdecrease; /* time for next possible decrease of rtt_variance */
  double rtt_mdev; /* smoothing of deviation from rtt_smoothed */
  double rtt_mdev_max; /* maximum of rtt_mdev since last possible decrease */
  double rto; /* retransmission timeout */

  /* BBR delivery-rate variables: */

  int bbrinit_happened;

  long long netbytesdelivered; /* total number of bytes known to be delivered */
  double netbytesdelivered_time; /* time of last update to netbytesdelivered */
  double first_sent_time; /* send time of packet most recently acknowledged */

  double bbr_pacing_rate; /* number of bytes desired on network per second */

  long long bbr_cwnd; /* number of bytes allowed on network per rtt */

  int bbr_state;
  int bbr_cycle_index;
  double bbr_cycle_stamp;
  struct windowedmax bbr_bandwidthfilter;
  double bbr_rtprop;
  double bbr_rtprop_stamp;
  int bbr_rtprop_expired;
  double bbr_probe_rtt_done_stamp;
  int bbr_probe_rtt_round_done;
  int bbr_packet_conservation;
  long long bbr_prior_cwnd;
  int bbr_idle_restart;
  long long bbr_next_round_delivered;
  int bbr_round_start;
  long long bbr_round_count;
  int bbr_filled_pipe;
  long long bbr_full_bandwidth;
  long long bbr_full_bandwidth_count;
  long long bbr_nominal_bandwidth;
  long long bbr_bandwidth;
  double bbr_pacing_gain;
  double bbr_cwnd_gain;
  long long bbr_target_cwnd;
  double bbr_cwnd_rate;
  double bbr_rate; /* minimum of bbr_cwnd_rate and bbr_pacing_rate */
  double bbr_rateinv; /* 1/bbr_rate */

  long long bbr_bytes_lost;
  long long bbr_prior_inflight;
  long long bbr_now_inflight;

  long long bbr_prior_delivered;
  double bbr_prior_time;
  double bbr_send_elapsed;
  double bbr_ack_elapsed;
  double bbr_interval;
  long long bbr_delivered;
  long long bbr_delivery_rate;
} ;

void pacing_connection_init(struct pacing_connection *cstorage)
{
  struct connection *c = (void *) cstorage;

  c->now = 0;
  c->lastsending = 0;
  c->bytesinflight = 0;
  c->packetssent = 0;
  c->packetsreceived = 0;
  c->pacing_when = 0;
  c->pacing_netbytes = 0;
  c->rtt_measured = 0;
  c->rtt_smoothed = 0;
  c->rtt_variance = 0;
  c->rtt_nextdecrease = 0;
  c->rtt_mdev = 0;
  c->rtt_mdev_max = 0;
  c->rto = 1;

  c->bbrinit_happened = 0;

  pacing_now_update(cstorage);
}

/* ----- windowed max */
/* basically the linux windowed minmax code, modulo data types */
/* skip windowedmin: user can negate input */

static double windowedmax_get(const struct windowedmax *m)
{
  return m->s[0].v;
}

static void windowedmax_reset(struct windowedmax *m,double t,double v)
{
  m->s[2].t = m->s[1].t = m->s[0].t = t;
  m->s[2].v = m->s[1].v = m->s[0].v = v;
}

static void windowedmax_subwin_update(struct windowedmax *m,double window,double t,double v)
{
  double dt = t-(m->s[0].t);

  if (dt > window) {
    m->s[0] = m->s[1];
    m->s[1] = m->s[2];
    m->s[2].t = t;
    m->s[2].v = v;
    if (t-(m->s[0].t) > window) {
      m->s[0] = m->s[1];
      m->s[1] = m->s[2];
      m->s[2].t = t;
      m->s[2].v = v;
    }
  } else if (m->s[1].t == m->s[0].t && dt > window/4) {
    m->s[2].t = m->s[1].t = t;
    m->s[2].v = m->s[1].v = v;
  } else if (m->s[2].t == m->s[1].t && dt > window/2) {
    m->s[2].t = t;
    m->s[2].v = v;
  }
}

static void windowedmax_running_max(struct windowedmax *m,double window,double t,double v)
{
  if (v >= m->s[0].v || t-(m->s[2].t) > window) {
    windowedmax_reset(m,t,v);
    return;
  }
  if (v >= m->s[1].v) {
    m->s[2].t = m->s[1].t = t;
    m->s[2].v = m->s[1].v = v;
  } else if (v >= m->s[2].v) {
    m->s[2].t = t;
    m->s[2].v = v;
  }

  windowedmax_subwin_update(m,window,t,v);
}

/* ----- setting retransmission timeout */

/* generally imitate linux, which says it improves upon RFC 6298 */

static void setrto(struct connection *c,double rtt)
{
  double diff;

  if (rtt <= 0) return;

  if (!c->rtt_measured) {
    c->rtt_measured = 1;
    /* rfc 6298 "first rtt measurement" */
    c->rtt_smoothed = rtt;
    c->rtt_variance = 0.5*rtt;
    c->rtt_mdev = 0;
    c->rtt_mdev_max = 0;
    c->rtt_nextdecrease = c->now+2*rtt;
    if (c->packetssent > 1) c->rto = 3; /* rfc 6298 paragraph 5.7 */
    return;
  }

  diff = rtt;
  diff -= c->rtt_smoothed;
  c->rtt_smoothed += 0.125*diff;

  if (diff > 0)
    diff -= c->rtt_mdev;
  else {
    diff = -diff;
    diff -= c->rtt_mdev;

    /* slow down increase of mdev when rtt seems to be decreasing */
    if (diff > 0) diff *= 0.125;
  }

  c->rtt_mdev += 0.25*diff;
  if (c->rtt_mdev > c->rtt_mdev_max) {
    c->rtt_mdev_max = c->rtt_mdev;
    if (c->rtt_mdev > c->rtt_variance)
      c->rtt_variance = c->rtt_mdev;
  }

  c->rto = c->rtt_smoothed+4*c->rtt_variance+0.000001;

  if (c->now >= c->rtt_nextdecrease) {
    if (c->rtt_mdev_max < c->rtt_variance)
      c->rtt_variance -= 0.25*(c->rtt_variance-c->rtt_mdev_max);
    c->rtt_mdev_max = 0;
    c->rtt_nextdecrease = c->now+c->rtt_smoothed;
  }

  /* rfc 6298 says "should be rounded up to 1 second" */
  /* but linux normally rounds up to 0.2 seconds */
  if (c->rto < 0.2) c->rto = 0.2;
}

/* ----- BBR congestion control */

#define BBR_STARTUP 1
#define BBR_DRAIN 2
#define BBR_PROBEBANDWIDTH 3
#define BBR_PROBERTT 4

static void bbr_enterprobertt(struct connection *c)
{
  c->bbr_state = BBR_PROBERTT;
  c->bbr_pacing_gain = 1;
  c->bbr_cwnd_gain = 1;
}

static void bbr_enterstartup(struct connection *c)
{
  c->bbr_state = BBR_STARTUP;
  c->bbr_pacing_gain = 2.88539;
  c->bbr_cwnd_gain = 2.88539;
}

static void bbr_enterdrain(struct connection *c)
{
  c->bbr_state = BBR_DRAIN;
  c->bbr_pacing_gain = 0.34657359;
  c->bbr_cwnd_gain = 2.88539;
}

static const double bbr_pacing_gain_cycle[8] = { 1.25, 0.75, 1, 1, 1, 1, 1, 1 };

static void bbr_advancecyclephase(struct connection *c)
{
  c->bbr_cycle_stamp = c->now;
  c->bbr_cycle_index = (c->bbr_cycle_index+1)&7;
  c->bbr_pacing_gain = bbr_pacing_gain_cycle[c->bbr_cycle_index];
}

static void bbr_enterprobebandwidth(struct connection *c)
{
  c->bbr_state = BBR_PROBEBANDWIDTH;
  c->bbr_pacing_gain = 1;
  c->bbr_cwnd_gain = 2;
  c->bbr_cycle_index = 1+(random()%7);
  bbr_advancecyclephase(c);
}

static void bbrinit(struct connection *c)
{
  if (c->bbrinit_happened) return;
  c->bbrinit_happened = 1;

  windowedmax_reset(&c->bbr_bandwidthfilter,0,0);
  c->bbr_rtprop = c->rtt_smoothed;
  if (c->rtt_smoothed == 0) c->bbr_rtprop = 86400;
  c->bbr_rtprop_stamp = c->now;
  c->bbr_probe_rtt_done_stamp = 0;
  c->bbr_probe_rtt_round_done = 0;
  c->bbr_packet_conservation = 0;
  c->bbr_prior_cwnd = 0;
  c->bbr_idle_restart = 0;

  c->bbr_next_round_delivered = 0;
  c->bbr_round_start = 0;
  c->bbr_round_count = 0;

  c->bbr_filled_pipe = 0;
  c->bbr_full_bandwidth = 0;
  c->bbr_full_bandwidth_count = 0;

  c->bbr_cwnd = INITCWND;

  if (c->rtt_smoothed)
    c->bbr_nominal_bandwidth = INITCWND/c->rtt_smoothed;
  else
    c->bbr_nominal_bandwidth = INITCWND/0.001;

  bbr_enterstartup(c);

  c->bbr_pacing_rate = c->bbr_pacing_gain*c->bbr_nominal_bandwidth;
  c->bbr_cwnd_rate = c->bbr_cwnd/c->rtt_smoothed;
  c->bbr_rate = c->bbr_cwnd_rate;
  if (c->bbr_rate > c->bbr_pacing_rate) c->bbr_rate = c->bbr_pacing_rate;
  c->bbr_rateinv = 1/c->bbr_rate;
}

static double bbrinflight(struct connection *c,double gain)
{
  if (c->bbr_rtprop == 86400) return INITCWND;
  return 0.99*gain*c->bbr_bandwidth*c->bbr_rtprop+4096;
}

static void bbr_checkcyclephase(struct connection *c)
{
  int is_full_length;

  if (c->bbr_state != BBR_PROBEBANDWIDTH) return;

  is_full_length = (c->now-c->bbr_cycle_stamp)>c->bbr_rtprop;
  if (c->bbr_pacing_gain == 1) {
    if (!is_full_length) return;
  } else if (c->bbr_pacing_gain > 1) {
    if (!is_full_length) return;
    if (c->bbr_bytes_lost == 0)
      if (c->bbr_prior_inflight < bbrinflight(c,c->bbr_pacing_gain)) return;
  } else {
    if (!is_full_length)
      if (c->bbr_prior_inflight > bbrinflight(c,1)) return;
  }
  bbr_advancecyclephase(c);
}

static void bbr_checkfullpipe(struct connection *c)
{
  if (!c->bbr_filled_pipe) return;
  if (!c->bbr_round_start) return;
  if (c->bbr_bandwidth >= c->bbr_full_bandwidth*1.25) {
    c->bbr_full_bandwidth = c->bbr_bandwidth;
    c->bbr_full_bandwidth_count = 0;
    return;
  }
  c->bbr_full_bandwidth_count += 1;
  if (c->bbr_full_bandwidth_count >= 3)
    c->bbr_filled_pipe = 1;
}

/* ----- BBR delivery-rate estimation */

static void bbrack(struct connection *c,struct packet *p,double packetrtt)
{
  long long bytes_delivered = p->len;
  double rate;

  bbrinit(c);

  c->bbr_bytes_lost = 0; /* XXX: see above regarding negative acknowledgments */
  c->bbr_prior_inflight = c->bytesinflight;
  c->bbr_now_inflight = c->bbr_prior_inflight-bytes_delivered;

  c->netbytesdelivered += bytes_delivered;
  c->netbytesdelivered_time = c->now;

  if (p->save_netbytesdelivered > c->bbr_prior_delivered) {
    c->bbr_prior_delivered = p->save_netbytesdelivered;
    c->bbr_prior_time = p->save_netbytesdelivered_time;
    c->bbr_send_elapsed = p->transmissiontime-p->first_sent_time;
    c->bbr_ack_elapsed = c->netbytesdelivered_time-c->bbr_prior_time;
    c->first_sent_time = p->transmissiontime;
  }

  if (c->bbr_prior_time != 0) {
    c->bbr_interval = c->bbr_send_elapsed;
    if (c->bbr_ack_elapsed > c->bbr_interval) c->bbr_interval = c->bbr_ack_elapsed;
    
    c->bbr_delivered = c->netbytesdelivered-c->bbr_prior_delivered;
  
    if (c->bbr_interval < c->rtt_smoothed) /* XXX: replace with bbr_minrtt */
      c->bbr_interval = -1;
    else if (c->bbr_interval > 0)
      c->bbr_delivery_rate = c->bbr_delivered/c->bbr_interval;
  }

  c->bbr_delivered += bytes_delivered;
  if (p->save_netbytesdelivered >= c->bbr_next_round_delivered) {
    c->bbr_next_round_delivered = c->bbr_delivered;
    c->bbr_round_count += 1;
    c->bbr_round_start = 1;
  } else
    c->bbr_round_start = 0;

  if (c->bbr_delivery_rate >= c->bbr_bandwidth) {
    windowedmax_running_max(&c->bbr_bandwidthfilter,10,c->bbr_round_count,c->bbr_delivery_rate);
    c->bbr_bandwidth = windowedmax_get(&c->bbr_bandwidthfilter);
  }

  bbr_checkcyclephase(c);
  bbr_checkfullpipe(c);

  if (c->bbr_state == BBR_STARTUP && c->bbr_filled_pipe)
    bbr_enterdrain(c);
  if (c->bbr_state == BBR_DRAIN && c->bbr_now_inflight <= bbrinflight(c,1))
    bbr_enterprobebandwidth(c);

  c->bbr_rtprop_expired = (c->now>c->bbr_rtprop_stamp+10);
  if (packetrtt >= 0)
    if (packetrtt <= c->bbr_rtprop || c->bbr_rtprop_expired) {
      c->bbr_rtprop = packetrtt;
      c->bbr_rtprop_stamp = c->now;
    }

  if (c->bbr_state != BBR_PROBERTT)
    if (c->bbr_rtprop_expired)
      if (!c->bbr_idle_restart) {
        bbr_enterprobertt(c);

        /* XXX: do this only if not in lossrecovery */
        c->bbr_prior_cwnd = c->bbr_cwnd;

        c->bbr_probe_rtt_done_stamp = 0;
      }
  if (c->bbr_state == BBR_PROBERTT) {
    if (c->bbr_probe_rtt_done_stamp == 0 && c->bbr_now_inflight <= MINCWND) {
      c->bbr_probe_rtt_done_stamp = c->now+0.2;
      c->bbr_probe_rtt_round_done = 0;
      c->bbr_next_round_delivered = c->bbr_delivered;
    } else if (c->bbr_probe_rtt_done_stamp) {
      if (c->bbr_round_start)
        c->bbr_probe_rtt_round_done = 1;
      if (c->bbr_probe_rtt_round_done)
        if (c->now > c->bbr_probe_rtt_done_stamp) {
          c->bbr_rtprop_stamp = c->now;
          if (c->bbr_cwnd < c->bbr_prior_cwnd) c->bbr_cwnd = c->bbr_prior_cwnd;
          if (c->bbr_filled_pipe)
            bbr_enterprobebandwidth(c);
          else
            bbr_enterstartup(c);
        }
    }
  }

  c->bbr_idle_restart = 0;

  rate = c->bbr_pacing_gain*c->bbr_bandwidth;
  if (c->bbr_filled_pipe || rate > c->bbr_pacing_rate)
    c->bbr_pacing_rate = rate;

  c->bbr_target_cwnd = bbrinflight(c,c->bbr_cwnd_gain);

  if (c->bbr_bytes_lost > 0) {
    c->bbr_cwnd -= c->bbr_bytes_lost;
    if (c->bbr_cwnd < 1600) c->bbr_cwnd = 1600;
  }
  if (!c->bbr_packet_conservation) {
    if (c->bbr_cwnd < c->bbr_now_inflight+bytes_delivered)
      c->bbr_cwnd = c->bbr_now_inflight+bytes_delivered;
    if (!c->bbr_packet_conservation) {
      if (c->bbr_filled_pipe) {
        c->bbr_cwnd += bytes_delivered;
        if (c->bbr_cwnd > c->bbr_target_cwnd)
          c->bbr_cwnd = c->bbr_target_cwnd;
      } else if (c->bbr_cwnd < c->bbr_target_cwnd || c->bbr_delivered < INITCWND)
        c->bbr_cwnd += bytes_delivered;
      if (c->bbr_cwnd < MINCWND) c->bbr_cwnd = MINCWND;
    }
  }

  if (c->bbr_state == BBR_PROBERTT)
    if (c->bbr_cwnd < MINCWND) c->bbr_cwnd = MINCWND;

  c->bbr_cwnd_rate = c->bbr_cwnd/c->rtt_smoothed;
  c->bbr_rate = c->bbr_cwnd_rate;
  if (c->bbr_rate > c->bbr_pacing_rate) c->bbr_rate = c->bbr_pacing_rate;
  c->bbr_rateinv = 1/c->bbr_rate;
}

/* ----- pacing */

static void pacing_rememberpacket(struct connection *c,long long bytes)
{
  if (!c->pacing_when || (c->now-c->pacing_when > 0.5*c->rtt_smoothed)) {
    c->pacing_when = c->now;
    c->pacing_netbytes = 0;
    return;
  }

  c->pacing_netbytes += c->bbr_rate*(c->now-c->pacing_when);
  c->pacing_when = c->now;

  c->pacing_netbytes -= bytes;
}

/* ----- something happened with a packet */

void pacing_now_update(struct pacing_connection *cstorage)
{
  struct connection *c = (void *) cstorage;
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC,&t);
  c->now = t.tv_sec+0.000000001*t.tv_nsec;
}

void pacing_packet_init(struct pacing_packet *pstorage,long long len)
{
  struct packet *p = (void *) pstorage;
  p->len = len;
  p->transmissions = 0;
  p->acknowledged = 0;
  p->transmissiontime = 0;
}

void pacing_transmitted(struct pacing_connection *cstorage,struct pacing_packet *pstorage)
{
  struct connection *c = (void *) cstorage;
  struct packet *p = (void *) pstorage;
  int firsttransmission = !p->transmissions;

  p->transmissions += 1;
  p->transmissiontime = c->now;

  if (c->packetssent == 0 || c->now-c->lastsending > 1) {
    /* XXX: consider more serious reset of state */
    c->netbytesdelivered_time = c->now;
    c->first_sent_time = c->now;
  }
  p->save_netbytesdelivered = c->netbytesdelivered;
  p->save_netbytesdelivered_time = c->netbytesdelivered_time;
  p->first_sent_time = c->first_sent_time;

  c->packetssent += 1;
  c->lastsending = c->now;

  pacing_rememberpacket(c,p->len);

  if (firsttransmission)
    c->bytesinflight += p->len;
  else {
    c->rto *= 2; /* rfc 6298 paragraph 5.5 */
    if (c->rto > 120) c->rto = 120;
  }
}

void pacing_acknowledged(struct pacing_connection *cstorage,struct pacing_packet *pstorage)
{
  struct connection *c = (void *) cstorage;
  struct packet *p = (void *) pstorage;
  if (p->acknowledged) return;
  p->acknowledged = 1;

  c->packetsreceived += 1;

  /* karn's algorithm: ignore RTT for retransmitted packets */
  /* XXX: transport protocol that can figure out ack for retransmission can reset transmissions, transmissiontime */
  if (p->transmissions == 1) {
    double rtt = c->now-p->transmissiontime;
    setrto(c,rtt);
    bbrack(c,p,rtt);
  }

  c->bytesinflight -= p->len;
}

double pacing_whendecongested(struct pacing_connection *cstorage,long long bytes)
{
  struct connection *c = (void *) cstorage;
  double decongest;

  if (!c->packetsreceived) {
    if (!c->packetssent)
      return 0; /* our very first packet; send immediately */
    return c->lastsending+0.5*c->packetssent-c->now; /* XXX: randomize a bit? */
  }

  if (c->bytesinflight >= c->bbr_cwnd)
    return c->lastsending+c->rto-c->now;
  
  if (c->bbr_rate*c->rtt_smoothed < bytes) {
    decongest = c->lastsending+c->rtt_smoothed;
  } else {
    bytes -= c->pacing_netbytes;
    decongest = c->pacing_when+bytes*c->bbr_rateinv;
    if (decongest > c->lastsending+c->rtt_smoothed) decongest = c->lastsending+c->rtt_smoothed;
  }
  return decongest-c->now;
}

double pacing_whenrto(struct pacing_connection *cstorage,struct pacing_packet *pstorage)
{
  struct connection *c = (void *) cstorage;
  struct packet *p = (void *) pstorage;
  if (p->transmissions) return p->transmissiontime+c->rto-c->now;
  return 0;
}
