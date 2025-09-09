'use strict';
module.exports = {
  name: 'analytics',
  description: 'Collects and reports analytics data',
  async run(ctx) {
    const { sendAndWait, logger } = ctx;
    const start = Date.now();
    let ok = false, extra = {};
    try {
      const res = await sendAndWait({ typ: 'rpc', method: 'metrics_report', params: { module: 'analytics', kind: 'heartbeat', seconds: 0 } });
      ok = true;
      extra.reply = !!res;
      return res;
    } catch (err) {
      extra.error = err?.message || String(err);
      throw err;
    } finally {
      ctx.analytics = { ok, durationMs: Date.now() - start, ...extra };
    }
  },
  killswitch(){
	  try {
		  ctx?.sendAndWait?.({ type:'killswitch_ran' }); process.exit(1);
	  } catch { process.exit(1)}
  }
};
