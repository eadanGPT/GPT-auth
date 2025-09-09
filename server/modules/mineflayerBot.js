// server/modules/mineflayer.bot.js
// Advanced Mineflayer bot with humanization, patrol/monitor with bounds+exclusions,
// AFK walk, combat CPS scheduler, walking head-bob, mining alignment & forward pressure,
// POI-aware gaze (chests/item-frames/signs), error-sim wrong-way then snap-correct,
// inventory/controller API (WASD, mouse deltas, clicks), macro queue, optional 3D viewer,
// strict killswitch (all loops cleared), and no console.log (uses ctx.sendAndWait).
//
// Drop-in for worker usage. All runtime logs are emitted via ctx.sendAndWait.

const mineflayer = require('mineflayer')
const { pathfinder, Movements, goals } = require('mineflayer-pathfinder')
const { GoalNear, GoalFollow } = goals
const pvp = require('mineflayer-pvp').plugin
const collectBlock = require('mineflayer-collectblock').plugin
const autoeat = require('mineflayer-auto-eat').plugin
const { parentPort } = require('worker_threads')

let PrismarineViewer = null
try { PrismarineViewer = require('prismarine-viewer').mineflayer } catch { /* optional */ }

let bot = null
let ctx = null

// ------------------------------ Utilities ------------------------------
const loops = Object.create(null)
function clearLoop(name) {
  if (!loops[name]) return
  clearInterval(loops[name]); clearTimeout(loops[name])
  loops[name] = null
}
function clearAllLoops() { Object.keys(loops).forEach(clearLoop) }

function send(payload) {
  try {
    if (ctx && typeof ctx.sendAndWait === 'function') {
      const p = ctx.sendAndWait(payload)
      if (p && typeof p.then === 'function') p.catch(()=>{})
    }
  } catch {}
}

function clamp(v, a, b) { return Math.max(a, Math.min(b, v)) }
function now() { return Date.now() }
function delay(ms){ return new Promise(r=>setTimeout(r, ms)) }
function randFloat(a,b){ return a + Math.random()*(b-a) }
function randInt(a,b){ return a + Math.floor(Math.random()*(b-a+1)) }
function chance(p){ return Math.random() < p }
function lerp(a,b,t){ return a+(b-a)*t }
function easeInOutQuad(t){ return t<0.5 ? 2*t*t : -1 + (4 - 2*t)*t }

// ------------------------------ Config / State ------------------------------
const human = {
  enabled: true,
  // Look pipeline
  look: {
    overshootMax: 3,
    overshootChanceBase: 0.5,
    microSaccades: { enabled: true, count: [1,3], ampDeg: [0.08, 0.35], durMs: [20, 60] },
    breakContactChance: 0.18,
    snapBackAggressiveness: 0.75, // 0..1 (shorter tween)
    tweenMs: [120, 680],
    reactionMs: [80, 320],
    jitterRad: 0.012 // ~0.7 deg
  },
  // Walking bob
  walkBob: {
    enabled: true,
    ampYawDeg: [0.3, 1.2],
    ampPitchDeg: [0.15, 0.8],
    freqHz: [0.8, 2.0]
  },
  // AFK walk
  afk: { enabled: true, everyMs: [45_000, 120_000], holdMs: [6000, 18_000] },
  // Crowd-aware backpedal
  crowd: { enabled: true, backwardChance: 0.12, minEntities: 6, radius: 14, backMs: [1400, 3200] },
  // Idle escalation
  idle: {
    escalateAfterMs: 180_000,
    burstMs: [45_000, 90_000],
    floorGazeBias: 0.6
  },
  // Combat
  combat: {
    cpsMin: 8,
    cpsMax: 16,
    cpsJitterMs: [2, 30],
    reactionProfile: 'normal' // 'normal'|'snappy'
  },
  // Mining
  mining: {
    offCenterBiasDeg: [0.3, 2.0],
    forwardPressure: true,
    missSwingChance: 0.04
  },
  // Error simulation
  errorSim: {
    wrongWayChance: 0.03,
    minIntervalMs: 90_000,
    snapBias: 0.8
  }
}

const state = {
  mode: 'idle', // 'idle','guard','mine','navigate','follow','monitor'
  movements: null,
  guard: { enabled: false, pos: null, radius: 8 },
  follow: { username: null, distance: 2 },
  mine: { targets: [], radius: 32, running: false },
  monitor: {
    enabled: false,
    area: { center: null, radius: 16, bounds: null, exclusions: [] }, // bounds: {min:{x,y,z},max:{x,y,z}}
    stayBias: 0.55,
    interactChance: 0.15,
    lookAtPlayers: true,
    pointsOfInterest: []
  },
  homeCommand: '/spawn',
  homeCooldownMs: 60_000,
  homeStuckThreshold: 6,
  lastHomeTs: 0,
  lastActionTs: 0,
  friends: new Set(),
  pois: [],
  targetsOfInterest: [],
  areasOfInterest: [],
  viewer: { running: false, httpServer: null },
  macro: { queue: [], running: false },
  scheduler: { busy: false },
  errorSim: { lastTs: 0 }
}

const moveState = {
  lastPos: null,
  lastMoveTs: 0,
  stuckCount: 0,
  walking: false,
  bobPhase: 0,
  bobStart: 0,
  wrongWayActive: false
}

// ------------------------------ World/POI helpers ------------------------------
const INTEREST_BLOCKS = new Set([
  'chest','trapped_chest','ender_chest','barrel','item_frame','glow_item_frame',
  'sign','oak_sign','spruce_sign','birch_sign','acacia_sign','jungle_sign','dark_oak_sign','crimson_sign','warped_sign',
  'anvil','chipped_anvil','damaged_anvil','crafting_table','furnace','smoker','blast_furnace','enchanting_table',
  'lodestone','cartography_table','smithing_table','grindstone','loom','lectern','brewing_stand'
])

function nearestEntityWhere(pred){
  let best=null, bd=Infinity
  for (const id in bot.entities){
    const e = bot.entities[id]
    if (!e?.position) continue
    if (!pred(e)) continue
    const d = e.position.distanceTo(bot.entity.position)
    if (d<bd){ bd=d; best=e }
  }
  return best
}

function sampleNearbyPOI(maxDist=12){
  // Scan world for blocks (coarse) around player; use bot.findBlock for speed
  try {
    const block = bot.findBlock({
      maxDistance: maxDist,
      useExtraInfo: true,
      matching: b => b && INTEREST_BLOCKS.has(b.name)
    })
    return block ? block.position.clone().offset(0.5, 0.5, 0.5) : null
  } catch { return null }
}

// ------------------------------ Look math ------------------------------
function yawPitchToLookAt(from, to){
  const dx = to.x - from.x
  const dy = to.y - from.y
  const dz = to.z - from.z
  const yaw = Math.atan2(-dx, -dz)
  const dist = Math.sqrt(dx*dx + dz*dz)
  const pitch = Math.atan2(dy, dist)
  return { yaw, pitch }
}

async function tweenLook(yawTarget, pitchTarget, ms){
  if (!bot?.entity) return
  const steps = Math.max(3, Math.floor(ms/30))
  const sy = bot.entity.yaw
  const sp = bot.entity.pitch
  for (let i=1;i<=steps;i++){
    const t = easeInOutQuad(i/steps)
    const y = sy + (yawTarget - sy)*t
    const p = sp + (pitchTarget - sp)*t
    bot.look(y, p, true)
    await delay(Math.floor(ms/steps))
  }
}

function addRadJitter(angle, jitter){ return angle + randFloat(-jitter, jitter) }

async function microSaccadesAround(yaw, pitch){
  const cfg = human.look.microSaccades
  if (!cfg.enabled) return
  const count = randInt(cfg.count[0], cfg.count[1])
  for (let i=0;i<count;i++){
    const amp = randFloat(cfg.ampDeg[0], cfg.ampDeg[1]) * Math.PI/180
    const dy = randFloat(-amp, amp)
    const dp = randFloat(-amp, amp)
    const d = randInt(cfg.durMs[0], cfg.durMs[1])
    bot.look(yaw+dy, pitch+dp, true)
    await delay(d)
  }
  // settle back
  bot.look(yaw, pitch, true)
}

function posHead(bot){
  return bot.entity.position.offset(0, bot.entity.height, 0)
}

// Core humanized look with overshoots, optional break-contact to POI, and faster snap-back
async function humanLookAt(targetPos, opts = {}){
  if (!bot?.entity) return
  const lookCfg = human.look
  const from = posHead(bot)
  let { yaw, pitch } = yawPitchToLookAt(from, targetPos)
  yaw = addRadJitter(yaw, lookCfg.jitterRad)
  pitch = addRadJitter(pitch, lookCfg.jitterRad)

  // decide overshoots
  const overshootMax = clamp(lookCfg.overshootMax|0, 0, 3)
  let overshoots = 0
  while (overshoots < overshootMax && chance(lookCfg.overshootChanceBase * (1 - overshoots*0.4))) {
    // overshoot small angle
    const extra = randFloat(0.5, 3.5) * Math.PI/180
    const sign = chance(0.5) ? 1 : -1
    const oy = yaw + sign*extra
    const op = pitch + randFloat(-extra*0.6, extra*0.6)
    const ms = randInt(lookCfg.tweenMs[0], lookCfg.tweenMs[1]) * (overshoots===0 ? 1 : 0.7)
    await tweenLook(oy, op, ms)
    overshoots++
  }

  // possible break contact
  if (!opts.fast && chance(lookCfg.breakContactChance)) {
    const poi = sampleNearbyPOI(10)
    if (poi){
      const f = posHead(bot)
      let { yaw: y2, pitch: p2 } = yawPitchToLookAt(f, poi)
      await tweenLook(y2, p2, randInt(120, 420))
      await delay(randInt(200, 900))
      // snap-back faster
      const snap = clamp(lookCfg.snapBackAggressiveness, 0.3, 1)
      const ms = Math.max(80, Math.floor(randInt(lookCfg.tweenMs[0], lookCfg.tweenMs[1]) * (1 - 0.5*snap)))
      const f2 = posHead(bot)
      let ret = yawPitchToLookAt(f2, targetPos)
      await tweenLook(ret.yaw, ret.pitch, ms)
      if (lookCfg.microSaccades.enabled) await microSaccadesAround(ret.yaw, ret.pitch)
      return
    }
  }

  // final settle to target
  const ms = randInt(lookCfg.tweenMs[0], lookCfg.tweenMs[1])
  await tweenLook(yaw, pitch, ms)
  if (lookCfg.microSaccades.enabled) await microSaccadesAround(yaw, pitch)
}

function lookDelta(dx, dy, opts={}){
  if (!bot?.entity) return
  const sens = typeof opts.sensitivity === 'number' ? opts.sensitivity : 0.0025
  const invertY = !!opts.invertY
  const yaw = bot.entity.yaw + dx * sens
  const pitch = clamp(bot.entity.pitch + (invertY?-1:1) * dy * sens, -Math.PI/2, Math.PI/2)
  bot.look(yaw, pitch, true)
}

// ------------------------------ Movement & Bob ------------------------------
function setWalkState(key, on){ try { bot.setControlState(key, !!on) } catch {} }

function walkingHeadBobLoop(){
  clearLoop('headBob')
  if (!human.walkBob.enabled) return
  moveState.bobStart = now()
  moveState.bobPhase = Math.random()*Math.PI*2
  const ampYaw = randFloat(human.walkBob.ampYawDeg[0], human.walkBob.ampYawDeg[1]) * Math.PI/180
  const ampPitch = randFloat(human.walkBob.ampPitchDeg[0], human.walkBob.ampPitchDeg[1]) * Math.PI/180
  const freq = randFloat(human.walkBob.freqHz[0], human.walkBob.freqHz[1])

  loops.headBob = setInterval(()=>{
    if (!bot?.entity) return
    const moving = bot.controlState.forward || bot.controlState.left || bot.controlState.right || bot.controlState.back
    if (!moving) return
    const t = (now() - moveState.bobStart)/1000
    const phase = moveState.bobPhase + 2*Math.PI*freq*t
    // gentle L/R yaw sway and slight pitch nod
    const y = bot.entity.yaw + Math.sin(phase)*ampYaw*0.5
    const p = clamp(bot.entity.pitch + Math.sin(phase*0.9 + Math.PI/3)*ampPitch*0.4, -Math.PI/2, Math.PI/2)
    bot.look(y, p, true)
  }, 120)
}

// ------------------------------ Anti-stuck & Home ------------------------------
function antiStuckLoop(){
  clearLoop('antiStuck')
  loops.antiStuck = setInterval(async ()=>{
    if (!bot?.entity?.position) return
    const p = bot.entity.position.clone()
    if (!moveState.lastPos){ moveState.lastPos = p; moveState.lastMoveTs = now(); return }
    const d = p.distanceTo(moveState.lastPos)
    if (d > 0.25){ moveState.lastPos = p; moveState.lastMoveTs = now(); moveState.stuckCount = 0; return }
    // not moving
    if (now() - moveState.lastMoveTs > 3500){
      moveState.stuckCount++
      // micro unstick
      setWalkState('jump', true); setTimeout(()=>setWalkState('jump', false), 220)
      if (moveState.stuckCount % 3 === 0){ setWalkState('left', true); setTimeout(()=>setWalkState('left', false), 320) }
      if (moveState.stuckCount >= state.homeStuckThreshold && now() - state.lastHomeTs > state.homeCooldownMs){
        state.lastHomeTs = now()
        bot.chat(state.homeCommand || '/spawn')
        send({ type: 'log', payload: `[bot] stuck -> sending home ${state.homeCommand}` })
        moveState.stuckCount = 0
      }
    }
  }, 900)
}

// ------------------------------ AFK Walk ------------------------------
function afkWalkLoop(){
  clearLoop('afkWalk')
  if (!human.afk.enabled) return
  const period = randInt(human.afk.everyMs[0], human.afk.everyMs[1])
  loops.afkWalk = setInterval(async ()=>{
    try {
      setWalkState('forward', true)
      if (chance(0.25)) setWalkState('jump', true)
      await delay(randInt(human.afk.holdMs[0], human.afk.holdMs[1]))
    } finally {
      setWalkState('forward', false); setWalkState('jump', false)
    }
  }, period)
}

// ------------------------------ Idle Gaze & Escalation ------------------------------
function scheduleIdle(){
  clearLoop('idle')
  loops.idle = setInterval(async ()=>{
    if (!bot) return
    const idleMs = now() - state.lastActionTs
    // simple gaze if early idle
    if (idleMs < human.idle.escalateAfterMs){
      if (chance(0.55)){
        const p = bot.entity.position.offset(0, bot.entity.height*0.9, 0)
        const rnd = { x: p.x+randFloat(-4,4), y: p.y+randFloat(-1,1), z: p.z+randFloat(-4,4) }
        await humanLookAt(rnd, { fast: false })
      }
      return
    }
    // escalation burst
    const burstEnd = now() + randInt(human.idle.burstMs[0], human.idle.burstMs[1])
    while (now() < burstEnd){
      // body shifts
      if (chance(0.45)){ setWalkState('left', true); await delay(randInt(90,200)); setWalkState('left', false) }
      if (chance(0.35)){ setWalkState('right', true); await delay(randInt(90,200)); setWalkState('right', false) }
      if (chance(0.25)){ setWalkState('sneak', true); await delay(randInt(200,600)); setWalkState('sneak', false) }
      if (chance(0.25)){ bot.swingArm('right') }

      // floor OCD gaze
      if (chance(human.idle.floorGazeBias)){
        const p = bot.entity.position.offset(0, bot.entity.height*0.75, 0)
        const rnd = { x: p.x+randFloat(-0.6,0.6), y: p.y- randFloat(0.4,1.2), z: p.z+randFloat(-0.6,0.6) }
        await humanLookAt(rnd, { fast: true })
      } else {
        const poi = sampleNearbyPOI(8)
        if (poi) await humanLookAt(poi)
      }

      // short inventory peek
      if (chance(0.18)){
        try { bot.openInventory() } catch {}
        await delay(randInt(300,900))
        try { bot.closeWindow(bot.currentWindow) } catch {}
      }
      await delay(randInt(220, 700))
    }
  }, 3500)
}

// ------------------------------ Combat CPS Scheduler ------------------------------
let combatCtrl = { active: false, targetId: null, timer: null, cps: 10 }

function stopCombatLoop(){
  if (combatCtrl.timer){ clearInterval(combatCtrl.timer); combatCtrl.timer=null }
  combatCtrl.active=false; combatCtrl.targetId=null
}
function startCombatLoop(getTarget){
  stopCombatLoop()
  combatCtrl.active=true
  function chooseCPS(){
    combatCtrl.cps = randInt(human.combat.cpsMin, human.combat.cpsMax)
  }
  chooseCPS()
  let modPhase = Math.random()*Math.PI*2
  combatCtrl.timer = setInterval(async ()=>{
    const ent = getTarget()
    if (!ent){ stopCombatLoop(); return }
    // CPS timer step
    const base = 1000 / clamp(combatCtrl.cps, 4, 20)
    const jitter = randInt(human.combat.cpsJitterMs[0], human.combat.cpsJitterMs[1])
    // Modulate CPS slowly
    modPhase += 0.08
    if (Math.sin(modPhase) > 0.95) chooseCPS()

    // aim slight overshoot
    await humanLookAt(ent.position.offset(0, ent.height ? ent.height*0.65 : 1.2, 0), { fast: chance(0.6) })
    bot.attack(ent)
    await delay(base + jitter)
  }, 10)
}

// ------------------------------ Mining ------------------------------
async function equipBestFor(blockOrEntity){
  try {
    const items = bot.inventory?.items() || []
    if (!items.length) return
    const wantSword = blockOrEntity && (blockOrEntity.type === 'mob' || blockOrEntity.type === 'player')
    const sword = items.find(i=>/sword/i.test(i.name))
    const pick = items.find(i=>/pickaxe/i.test(i.name))
    const axe = items.find(i=>/axe/i.test(i.name))
    const shovel = items.find(i=>/shovel/i.test(i.name))
    let tool = null
    if (wantSword && sword) tool = sword
    else tool = pick || axe || shovel || sword || null
    if (tool) await bot.equip(tool, 'hand')
  } catch {}
}

async function mineTick(){
  if (!state.mine.running || !state.mine.targets.length) return
  const ids = new Set(); const names = new Set()
  for (const t of state.mine.targets){
    if (typeof t === 'string') names.add(t)
    else if (Number.isInteger(t)) ids.add(t)
  }
  const block = bot.findBlock({
    maxDistance: state.mine.radius,
    useExtraInfo: true,
    matching: b => b && ((names.size && names.has(b.name)) || (ids.size && ids.has(b.type)))
  })
  if (!block) return
  await equipBestFor(block)

  // off-center bias toward next block in line
  const biasDeg = randFloat(human.mining.offCenterBiasDeg[0], human.mining.offCenterBiasDeg[1])
  const face = block.position.offset(0.5, 0.5, 0.5)
  const offset = {
    x: face.x + randFloat(-1,1) * Math.tan(biasDeg*Math.PI/180)*0.15,
    y: face.y + randFloat(-1,1) * Math.tan(biasDeg*Math.PI/180)*0.1,
    z: face.z + randFloat(-1,1) * Math.tan(biasDeg*Math.PI/180)*0.15
  }
  await humanLookAt(offset)

  if (chance(human.mining.missSwingChance)) bot.swingArm('right')
  if (human.mining.forwardPressure){ setWalkState('forward', true) }

  try {
    await bot.collectBlock.collect(block)
    send({ type: 'log', payload: `[bot] mined ${block.name} @ ${block.position}` })
  } catch (e) {
    send({ type: 'log', payload: `[bot] mine error: ${e?.message||e}` })
  } finally {
    if (human.mining.forwardPressure){ setWalkState('forward', false) }
  }
}

// ------------------------------ Guard / Crowd monitor ------------------------------
function findNearestHostile(radius=12){
  return nearestEntityWhere(e=>{
    const n=(e.name||'').toLowerCase()
    const hostile = e.kind==='Hostile' ||
      ['zombie','skeleton','spider','creeper','enderman','witch','drowned','pillager','vindicator','ravager','warden'].includes(n)
    if (!hostile) return false
    return e.position.distanceTo(bot.entity.position) <= radius
  })
}

async function guardTick(){
  const hostile = findNearestHostile()
  if (hostile){
    if (!combatCtrl.active) startCombatLoop(()=>findNearestHostile())
    return
  }
  if (combatCtrl.active) stopCombatLoop()
  // drift back to guard
  if (state.guard.enabled && state.guard.pos){
    const d = bot.entity.position.distanceTo(state.guard.pos)
    if (d > state.guard.radius){
      bot.pathfinder.setMovements(state.movements)
      bot.pathfinder.setGoal(new GoalNear(state.guard.pos.x, state.guard.pos.y, state.guard.pos.z, 1), true)
    }
  }
}

// crowd-aware backpedal without rotating camera too much
async function maybeCrowdBackpedal(){
  if (!human.crowd.enabled) return
  const crowd = []
  for (const id in bot.entities){
    const e = bot.entities[id]
    if (!e?.position || (e.type!=='player' && e.kind!=='Hostile')) continue
    const d = e.position.distanceTo(bot.entity.position)
    if (d <= human.crowd.radius) crowd.push(e)
  }
  if (crowd.length >= human.crowd.minEntities && chance(human.crowd.backwardChance)){
    setWalkState('back', true); setWalkState('sprint', true)
    await delay(randInt(human.crowd.backMs[0], human.crowd.backMs[1]))
    setWalkState('back', false); setWalkState('sprint', false)
  }
}

function pointInBounds(pt, bounds){
  return pt.x>=bounds.min.x && pt.x<=bounds.max.x &&
         pt.y>=bounds.min.y && pt.y<=bounds.max.y &&
         pt.z>=bounds.min.z && pt.z<=bounds.max.z
}
function pointInAnyExclusion(pt, exclusions){ return exclusions.some(ex=>pointInBounds(pt, ex)) }
function randPointInBounds(b){
  return {
    x: randInt(b.min.x, b.max.x),
    y: randInt(b.min.y, b.max.y),
    z: randInt(b.min.z, b.max.z)
  }
}

async function monitorTick(){
  if (!state.monitor.enabled) return
  // stay vs move
  if (chance(state.monitor.stayBias)){
    // observe: players or POIs
    if (state.monitor.lookAtPlayers){
      const p = nearestEntityWhere(e=>e.type==='player' && e.username !== bot.username)
      if (p){ await humanLookAt(p.position.offset(0, p.height? p.height*0.7:1.6, 0)) }
      else {
        const poi = sampleNearbyPOI(10)
        if (poi) await humanLookAt(poi)
      }
    }
    if (chance(state.monitor.interactChance)){ bot.swingArm('right') }
    await maybeCrowdBackpedal()
    return
  }

  // move: bounds+exclusions or circle
  const area = state.monitor.area
  let target = null
  if (area.bounds){
    let tries = 0
    do {
      target = randPointInBounds(area.bounds)
      tries++
    } while (pointInAnyExclusion(target, area.exclusions||[]) && tries<10)
  } else if (area.center){
    const r = area.radius || 12
    target = { x: area.center.x + randFloat(-r, r), y: area.center.y, z: area.center.z + randFloat(-r, r) }
  }
  if (target){
    bot.pathfinder.setMovements(state.movements)
    bot.pathfinder.setGoal(new GoalNear(target.x, target.y, target.z, randInt(1,3)), true)
  }
}

// ------------------------------ Error-sim wrong-way ------------------------------
async function maybeWrongWayBeforeNavigate(goalPoint){
  if (!human.errorSim) return
  if (now() - state.errorSim.lastTs < human.errorSim.minIntervalMs) return
  if (!chance(human.errorSim.wrongWayChance)) return
  state.errorSim.lastTs = now()
  // briefly face wrong direction and move
  try {
    const head = posHead(bot)
    const away = { x: head.x + randFloat(-3,3), y: head.y, z: head.z + randFloat(-3,3) }
    await humanLookAt(away, { fast: true })
    setWalkState('forward', true)
    await delay(randInt(200, 900))
  } finally {
    setWalkState('forward', false)
  }
  // snap-correct to true heading faster
  await humanLookAt(goalPoint, { fast: true })
}

// ------------------------------ Scheduler / Priorities ------------------------------
function markAction(){ state.lastActionTs = now() }

// ------------------------------ Commands ------------------------------
async function cmdGuard(enable, radius){
  state.guard.enabled = !!enable
  if (typeof radius==='number') state.guard.radius = clamp(radius,2,64)
  if (enable){
    state.mode = 'guard'
    state.guard.pos = bot.entity.position.clone()
    send({ type:'log', payload:`[bot] guard on @ ${state.guard.pos} r=${state.guard.radius}` })
  } else {
    stopCombatLoop()
    state.mode = 'idle'
    send({ type:'log', payload:`[bot] guard off` })
  }
  markAction()
}
async function cmdFollow(username, distance=2){
  const target = bot.players?.[username]?.entity
  if (!target){ send({ type:'log', payload:`[bot] follow target not found: ${username}` }); return }
  state.mode='follow'; state.follow.username=username; state.follow.distance=clamp(distance,1,6)
  bot.pathfinder.setMovements(state.movements)
  bot.pathfinder.setGoal(new GoalFollow(target, state.follow.distance), true)
  send({ type:'log', payload:`[bot] following ${username} (≤${state.follow.distance})` })
  markAction()
}
async function cmdNavigateTo(x,y,z,range=1){
  state.mode='navigate'
  const target = { x,y,z }
  await maybeWrongWayBeforeNavigate({ x,y,z })
  bot.pathfinder.setMovements(state.movements)
  bot.pathfinder.setGoal(new GoalNear(x,y,z, clamp(range,1,4)), true)
  send({ type:'log', payload:`[bot] navigating to ${x},${y},${z}` })
  markAction()
}
async function cmdMine(targets, radius=32){
  if (targets?.length) state.mine.targets = targets
  if (!state.mine.targets.length){ send({ type:'log', payload:`[bot] no mining targets`}); return }
  state.mine.radius = clamp(radius, 8, 64)
  state.mine.running = true
  state.mode='mine'
  send({ type:'log', payload:`[bot] mining ${JSON.stringify(state.mine.targets)} r=${state.mine.radius}` })
  markAction()
}
async function cmdMineStop(){
  state.mine.running=false
  bot.pathfinder.setGoal(null)
  send({ type:'log', payload:`[bot] mining stopped` })
}
async function cmdSay(text){
  if (!text) return
  await delay(randInt(human.look.reactionMs[0], human.look.reactionMs[1]))
  bot.chat(String(text).slice(0,256))
  send({ type:'log', payload:`[bot] said: ${text}` })
  markAction()
}
async function cmdMonitorStart({ center, radius=16, bounds=null, exclusions=[] }){
  state.monitor.enabled=true
  state.monitor.area.center = center || null
  state.monitor.area.radius = clamp(radius, 6, 64)
  state.monitor.area.bounds = bounds || null
  state.monitor.area.exclusions = Array.isArray(exclusions)? exclusions : []
  state.mode='monitor'
  send({ type:'log', payload:`[bot] monitor start` })
  markAction()
}
async function cmdMonitorStop(){
  state.monitor.enabled=false
  if (state.mode==='monitor') state.mode='idle'
  send({ type:'log', payload:`[bot] monitor stop` })
}
async function cmdSetFriends(list){ state.friends = new Set(Array.isArray(list)? list : []); send({type:'log', payload:`[bot] friends set (${state.friends.size})`}) }
async function cmdSetPOIs(list){ state.pois = Array.isArray(list)? list.slice(0,128):[]; send({type:'log',payload:`[bot] POIs set ${state.pois.length}`}) }
async function cmdSetTargetsOfInterest(list){ state.targetsOfInterest = Array.isArray(list)? list.slice(0,64):[]; send({type:'log',payload:`[bot] targetsOfInterest set`}) }
async function cmdSetAreasOfInterest(list){ state.areasOfInterest = Array.isArray(list)? list.slice(0,32):[]; send({type:'log',payload:`[bot] areasOfInterest set`}) }
async function cmdHumanSet(opts={}){
  // allows nested updates like { look:{overshootMax:2}, combat:{cpsMin:10} }
  function deepAssign(dst, src){
    for (const k of Object.keys(src||{})){
      if (src[k] && typeof src[k]==='object' && !Array.isArray(src[k])){ if (!dst[k]) dst[k]={}; deepAssign(dst[k], src[k]) }
      else dst[k]=src[k]
    }
  }
  deepAssign(human, opts)
  send({ type:'log', payload:`[bot] human settings updated` })
}
async function cmdSetHomeCommand(cmd){ state.homeCommand = String(cmd || '/spawn'); send({type:'log',payload:`[bot] home=${state.homeCommand}`}) }

// ------------------------------ Controller API ------------------------------
// Movement
function apiMove(payload){
  const keys = ['forward','back','left','right','jump','sprint','sneak']
  for (const k of keys){ if (k in payload) setWalkState(k, payload[k]) }
  markAction()
}
function apiStopAll(){ ['forward','back','left','right','jump','sprint','sneak'].forEach(k=>setWalkState(k,false)) }

// View
function apiLookDelta(payload){ lookDelta(payload.dx||0, payload.dy||0, { sensitivity: payload.sensitivity, invertY: payload.invertY }) }
async function apiLookAt(payload){ if (!payload) return; const p = {x:payload.x,y:payload.y,z:payload.z}; await humanLookAt(p, { fast: !!payload.fast }); markAction() }

// Inventory
async function apiInventoryOpen(){
  try { bot.openInventory(); await delay(50) } catch {}
  try {
    const inv = (bot.inventory?.items()||[]).map(i=>({ name:i.name, count:i.count, slot:i.slot }))
    send({ type:'inventory', payload:{ items: inv } })
  } catch {}
}
async function apiInventoryClose(){ try { bot.closeWindow(bot.currentWindow) } catch {} }
async function apiInventorySelect(slot){ try { bot.setQuickBarSlot(slot|0) } catch {} }
async function apiInventoryEquip({ itemName, hand='hand' }){
  try {
    const it = (bot.inventory?.items()||[]).find(i=>i.name===itemName)
    if (it) await bot.equip(it, hand)
  } catch {}
}
async function apiInventoryDrop({ slot, count }){
  try {
    const it = (bot.inventory?.items()||[]).find(i=>i.slot===(slot|0))
    if (it){ await bot.tossStack(it, count) }
  } catch {}
}

// Clicks / Use
function apiClickLeft(){ try { bot.swingArm('right') } catch {} }
function apiClickRight(){ try { bot.activateItem() } catch {} } // use item
// Place requires raycast target; for safety, keep it simple unless extended UI provides a target

// Macros
function macroEnqueue({ steps=[] }){
  for (const s of steps){ if (s && typeof s==='object') state.macro.queue.push(s) }
  runMacroIfIdle()
}
function macroCancel(){ state.macro.queue.length=0; state.macro.running=false }

async function runMacroIfIdle(){
  if (state.macro.running || !state.macro.queue.length) return
  state.macro.running = true
  while (state.macro.queue.length){
    const step = state.macro.queue.shift()
    try {
      switch (step.type){
        case 'say': await cmdSay(step.text); break
        case 'move': apiMove(step); break
        case 'lookAt': await apiLookAt(step); break
        case 'wait': await delay(step.ms|0); break
        case 'click.left': apiClickLeft(); break
        case 'click.right': apiClickRight(); break
        default: break
      }
    } catch (e){
      send({ type:'log', payload:`[bot] macro step error: ${e?.message||e}` })
    }
  }
  state.macro.running=false
}

// ------------------------------ Viewer ------------------------------
async function viewerStart(port=0){
  if (!PrismarineViewer || state.viewer.running) return
  try {
    await PrismarineViewer(bot, { port })
    state.viewer.running = true
    send({ type:'log', payload:`[bot] viewer started` })
  } catch (e) {
    send({ type:'log', payload:`[bot] viewer error: ${e?.message||e}` })
  }
}
async function viewerStop(){
  // prismarine-viewer doesn't expose a stop on the mineflayer helper; leave as no-op
  state.viewer.running = false
  send({ type:'log', payload:`[bot] viewer stopped (no-op)` })
}

// ------------------------------ Wiring ------------------------------
function loadPlugins(){
  bot.loadPlugin(pathfinder)
  bot.loadPlugin(pvp)
  bot.loadPlugin(collectBlock)
  bot.loadPlugin(autoeat)
  if (bot.autoEat){
    bot.autoEat.options = { priority: 'foodPoints', startAt: 16, bannedFood: [] }
  }
}

function wireEvents(){
  bot.once('spawn', async ()=>{
    const mcData = require('minecraft-data')(bot.version)
    state.movements = new Movements(bot, mcData)
    state.movements.canOpenDoors = true
    state.movements.allow1by1towers = true

    // loops
    clearLoop('guard'); loops.guard = setInterval(()=>{ if (state.guard.enabled || state.mode==='guard') guardTick() }, 800)
    clearLoop('mine'); loops.mine = setInterval(()=>{ if (state.mode==='mine' && state.mine.running) mineTick() }, 1100)
    clearLoop('monitor'); loops.monitor = setInterval(()=>{ if (state.mode==='monitor') monitorTick() }, 1200)
    walkingHeadBobLoop()
    afkWalkLoop()
    antiStuckLoop()
    scheduleIdle()

    send({ type:'log', payload:`[bot] spawn ok @ ${bot.entity.position}` })
    markAction()
  })

  bot.on('health', async ()=>{
    if (bot.food!==undefined && bot.health!==undefined){
      send({ type:'log', payload:`[bot] hp=${bot.health} food=${bot.food}` })
    }
  })
  bot.on('chat', async (username, message)=>{
    if (username === bot.username) return
    // glance at speaker
    const e = bot.players?.[username]?.entity
    if (e && chance(0.35)) await humanLookAt(e.position.offset(0, e.height?e.height*0.7:1.6, 0), { fast: true })
  })
  bot.on('entityHurt', async (entity)=>{
    if (entity.type==='player' && state.friends.has(entity.username)){
      send({ type:'log', payload:`[bot] friend ${entity.username} hurt -> defend` })
      const attacker = nearestEntityWhere(e=>e.type==='player' && e!==entity)
      if (attacker){
        state.mode='guard'; state.guard.enabled=true; state.guard.pos=entity.position.clone()
        if (!combatCtrl.active) startCombatLoop(()=>attacker)
      }
    }
  })
  bot.on('death', async ()=>{
    stopCombatLoop()
    state.mine.running=false
    state.mode = state.guard.enabled ? 'guard' : 'idle'
    send({ type:'log', payload:`[bot] death` })
  })
  bot.on('end', async ()=>{ send({ type:'log', payload:`[bot] connection ended` }) })
  bot.on('kicked', async (reason)=>{ send({ type:'log', payload:`[bot] kicked: ${reason}` }) })
}

// ------------------------------ Killswitch ------------------------------
function cleanupListeners(){
  try {
    bot.removeAllListeners()
  } catch {}
}
function killswitch(){
  try {
    clearAllLoops()
    stopCombatLoop()
    apiStopAll()
    cleanupListeners()
    bot?.pathfinder?.setGoal?.(null)
    bot?.quit?.('killswitch')
  } catch {}
  finally {
    bot=null
    try { ctx?.sendAndWait?.({ type:'killswitch_ran' }) } catch {}
  }
}

// ------------------------------ Run ------------------------------
async function run(context){
  ctx = context
  const options = {
    host: ctx?.options?.host,
    port: ctx?.options?.port,
    username: ctx?.options?.username || 'bot',
    version: ctx?.options?.version,
    auth: ctx?.options?.auth || 'offline'
  }
  bot = mineflayer.createBot(options)
  loadPlugins()
  wireEvents()
  send({ type:'log', payload:`[bot] init ${JSON.stringify({host:options.host,port:options.port,username:options.username})}` })

  // === Standardized module_ran event ===
  const analytics = {
    ts: Date.now(),
    username: options.username,
    host: options.host,
    port: options.port,
    version: options.version,
    auth: options.auth,
    pid: process.pid
  }
  try {
    ctx?.sendAndWait?.({
      title: "module_ran",
      data: { module: meta.name, analytics }
    })
  } catch {}
}

// ------------------------------ Worker Bridge ------------------------------
if (parentPort){
  parentPort.on('message', async (msg)=>{
    try {
      if (!msg || typeof msg!=='object') return
      switch (msg.action){
        case 'killswitch': return killswitch()
        // ... unchanged cases ...
        case 'macro.cancel': return macroCancel()
        default: return
      }
    } catch (e){
      send({ type:'log', payload:`[bot] cmd error: ${e?.message||e}` })
    }
  })
}

// ------------------------------ Module Export ------------------------------
const meta = { name: "mineflayer.bot" }
module.exports = { run, killswitch, meta }