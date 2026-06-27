/**
 * UBI Landing — app.js
 * Vanilla JS, zero external dependencies.
 * All motion respects prefers-reduced-motion.
 */

(function () {
  'use strict';

  // ── Reduced motion gate ───────────────────────────────────────
  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ── Brand colors (kept in sync with styles.css tokens) ────────
  const C = {
    green:      '#4fe7a8',
    greenDim:   'rgba(79,231,168,0.18)',
    greenGlow:  'rgba(79,231,168,0.35)',
    violet:     '#8b7bff',
    violetDim:  'rgba(139,123,255,0.18)',
    blue:       '#9ec1ff',
    pohStart:   '#FFFF00',
    pohEnd:     '#FF6699',
    pohGreen:   '#009966',
    ink:        '#eef1f7',
    muted:      '#8b91a4',
    faint:      '#5b6072',
    line:       'rgba(255,255,255,0.08)',
    line2:      'rgba(255,255,255,0.14)',
    bg:         '#06060A',
  };

  // ── UBI accrual constants ──────────────────────────────────────
  // 1 UBI per hour = 1/3600 UBI per second
  const UBI_PER_SECOND = 1 / 3600;
  const startTime = performance.now();

  // ── Utility ───────────────────────────────────────────────────
  function lerp(a, b, t) { return a + (b - a) * t; }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function rand(lo, hi) { return lo + Math.random() * (hi - lo); }
  function randInt(lo, hi) { return Math.floor(rand(lo, hi + 1)); }

  // Cap device pixel ratio for performance
  function getDPR() { return Math.min(window.devicePixelRatio || 1, 2); }

  // Resize a canvas to match its CSS display size at a capped DPR
  function resizeCanvas(canvas) {
    const dpr = getDPR();
    const rect = canvas.getBoundingClientRect();
    const w = Math.round(rect.width * dpr);
    const h = Math.round(rect.height * dpr);
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width  = w;
      canvas.height = h;
      return true;
    }
    return false;
  }

  // ══════════════════════════════════════════════════════════════
  // 1. MOBILE NAV TOGGLE
  // ══════════════════════════════════════════════════════════════
  (function initNav() {
    const toggle = document.querySelector('.nav-toggle');
    const links  = document.getElementById('nav-links');
    if (!toggle || !links) return;

    toggle.addEventListener('click', () => {
      const open = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!open));
      links.classList.toggle('open', !open);
    });

    // Close on any link click
    links.querySelectorAll('a').forEach(a => {
      a.addEventListener('click', () => {
        toggle.setAttribute('aria-expanded', 'false');
        links.classList.remove('open');
      });
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 2. LIVE UBI COUNTER (hero + drip sidebar)
  //    Illustrative: shows continuous accrual at 1 UBI/hour
  // ══════════════════════════════════════════════════════════════
  (function initCounters() {
    const heroCounter = document.getElementById('ubi-counter');
    const dripCounter = document.getElementById('drip-counter');

    if (!heroCounter && !dripCounter) return;

    function tick() {
      const elapsed = (performance.now() - startTime) / 1000; // seconds
      const accrued = elapsed * UBI_PER_SECOND;
      const display = accrued.toFixed(6);

      if (heroCounter) heroCounter.textContent = display;
      if (dripCounter) dripCounter.textContent = display;

      requestAnimationFrame(tick);
    }

    if (REDUCED) {
      // Show static illustrative value
      if (heroCounter) heroCounter.textContent = '0.000277';
      if (dripCounter) dripCounter.textContent = '0.000277';
    } else {
      requestAnimationFrame(tick);
    }
  })();

  // ══════════════════════════════════════════════════════════════
  // 3. HERO NODE-NETWORK CANVAS
  //    Drifting nodes + connecting lines in accent hues
  // ══════════════════════════════════════════════════════════════
  (function initHeroCanvas() {
    const canvas = document.getElementById('hero-canvas');
    if (!canvas || REDUCED) return;

    const ctx = canvas.getContext('2d');
    const MAX_NODES   = 48;
    const MAX_DIST    = 160;
    const SPEED_SCALE = 0.22;

    let nodes = [];
    let W, H;

    function mkNode() {
      return {
        x:  rand(0, W),
        y:  rand(0, H),
        vx: rand(-SPEED_SCALE, SPEED_SCALE),
        vy: rand(-SPEED_SCALE, SPEED_SCALE),
        r:  rand(1.5, 3.5),
        hue: Math.random() < 0.5 ? C.green : C.violet,
        pulse: rand(0, Math.PI * 2),
        pulseSpeed: rand(0.02, 0.05),
      };
    }

    function setup() {
      resizeCanvas(canvas);
      W = canvas.width / getDPR();
      H = canvas.height / getDPR();
      nodes = [];
      for (let i = 0; i < MAX_NODES; i++) nodes.push(mkNode());
    }

    function draw() {
      resizeCanvas(canvas);
      const dpr = getDPR();
      W = canvas.width / dpr;
      H = canvas.height / dpr;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, W, H);

      // Move nodes
      nodes.forEach(n => {
        n.x += n.vx;
        n.y += n.vy;
        n.pulse += n.pulseSpeed;
        // Bounce off edges softly
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
        n.x = clamp(n.x, 0, W);
        n.y = clamp(n.y, 0, H);
      });

      // Draw edges
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < MAX_DIST) {
            const alpha = (1 - dist / MAX_DIST) * 0.22;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            // Mix green and violet based on the two node hues
            const isViolet = nodes[i].hue === C.violet && nodes[j].hue === C.violet;
            ctx.strokeStyle = isViolet
              ? `rgba(139,123,255,${alpha})`
              : `rgba(79,231,168,${alpha})`;
            ctx.lineWidth = 0.9;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      nodes.forEach(n => {
        const glow = 0.5 + 0.35 * Math.sin(n.pulse);
        const isGreen = n.hue === C.green;
        const rg = isGreen ? '79,231,168' : '139,123,255';

        // Outer glow halo
        const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 5);
        grad.addColorStop(0, `rgba(${rg},${glow * 0.35})`);
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 5, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${rg},${0.65 + glow * 0.3})`;
        ctx.fill();
      });

      ctx.restore();
      requestAnimationFrame(draw);
    }

    window.addEventListener('resize', setup);
    setup();
    requestAnimationFrame(draw);
  })();

  // ══════════════════════════════════════════════════════════════
  // 4. VOUCH GRAPH (PoH section)
  //    Animated social graph showing verified/pending nodes
  // ══════════════════════════════════════════════════════════════
  (function initVouchGraph() {
    const canvas = document.getElementById('vouch-graph');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Node definitions: type = 'verified' | 'pending' | 'juror'
    const nodeData = [
      // Verified humans (center cluster)
      { id: 0, type: 'verified', label: 'Alice',   cx: 0.50, cy: 0.30 },
      { id: 1, type: 'verified', label: 'Bob',     cx: 0.30, cy: 0.50 },
      { id: 2, type: 'verified', label: 'Carol',   cx: 0.70, cy: 0.50 },
      { id: 3, type: 'verified', label: 'Dave',    cx: 0.50, cy: 0.72 },
      // Pending verification
      { id: 4, type: 'pending',  label: 'Eve',     cx: 0.20, cy: 0.28 },
      { id: 5, type: 'pending',  label: 'Frank',   cx: 0.82, cy: 0.35 },
      // AI juror nodes
      { id: 6, type: 'juror',    label: 'Juror A', cx: 0.15, cy: 0.72 },
      { id: 7, type: 'juror',    label: 'Juror B', cx: 0.50, cy: 0.92 },
      { id: 8, type: 'juror',    label: 'Juror C', cx: 0.85, cy: 0.72 },
    ];

    // Edges: [from, to]
    const edges = [
      [0, 1], [0, 2], [1, 3], [2, 3],  // verified connections
      [1, 4], [0, 4],                   // vouching for Eve
      [2, 5], [0, 5],                   // vouching for Frank
      [4, 6], [4, 7], [4, 8],           // Eve gets juror verdicts
      [3, 6], [3, 7], [3, 8],           // Dave gets juror verdicts
    ];

    let t = 0;
    let W, H;

    // Animated packet positions along vouching edges
    const packets = edges.slice(0, 8).map((e, i) => ({
      edge: e,
      progress: (i / 8),
      speed: rand(0.003, 0.007),
    }));

    // Map type → [r,g,b] for safe canvas color construction
    function nodeRGB(type) {
      switch (type) {
        case 'verified': return [255, 255, 0];    // #FFFF00 pohStart
        case 'pending':  return [251, 191, 92];   // #fbbf5c
        case 'juror':    return [0, 153, 102];    // #009966 pohGreen
        default:         return [139, 145, 164];  // muted
      }
    }
    function nodeColor(type) {
      const [r,g,b] = nodeRGB(type);
      return `rgb(${r},${g},${b})`;
    }

    function draw() {
      resizeCanvas(canvas);
      const dpr = getDPR();
      W = canvas.width / dpr;
      H = canvas.height / dpr;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, W, H);

      t += 0.012;

      const nodes = nodeData.map(n => ({
        ...n,
        x: n.cx * W,
        y: n.cy * H,
        r: n.type === 'juror' ? 10 : 13,
      }));

      // Draw edges
      edges.forEach(([ai, bi]) => {
        const a = nodes[ai], b = nodes[bi];
        const isPending = a.type === 'pending' || b.type === 'pending';
        const isJuror = a.type === 'juror' || b.type === 'juror';
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        if (isJuror) {
          ctx.strokeStyle = `rgba(0,153,102,0.25)`;
          ctx.lineWidth = 1;
          ctx.setLineDash([4, 6]);
        } else {
          ctx.strokeStyle = isPending
            ? `rgba(251,191,92,0.2)`
            : `rgba(255,255,0,0.2)`;
          ctx.lineWidth = isPending ? 1 : 1.5;
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // Animate packets (only if motion allowed)
      if (!REDUCED) {
        packets.forEach(p => {
          p.progress += p.speed;
          if (p.progress > 1) p.progress = 0;
          const a = nodes[p.edge[0]], b = nodes[p.edge[1]];
          const px = lerp(a.x, b.x, p.progress);
          const py = lerp(a.y, b.y, p.progress);
          ctx.beginPath();
          ctx.arc(px, py, 3, 0, Math.PI * 2);
          ctx.fillStyle = nodeColor(a.type);
          ctx.fill();
        });
      }

      // Draw nodes
      nodes.forEach(n => {
        const pulse = REDUCED ? 1 : (0.85 + 0.15 * Math.sin(t + n.id));
        const [nr, ng, nb] = nodeRGB(n.type);
        const color = `rgb(${nr},${ng},${nb})`;

        // Glow
        const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 3.5);
        grad.addColorStop(0, `rgba(${nr},${ng},${nb},${0.3 * pulse})`);
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 3.5, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        // Ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.globalAlpha = 0.6 * pulse;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Core
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 0.55, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.85 * pulse;
        ctx.fill();
        ctx.globalAlpha = 1;

        // Label
        ctx.font = `600 10px ${getComputedStyle(document.documentElement).fontFamily || 'system-ui'}`;
        ctx.fillStyle = C.muted;
        ctx.textAlign = 'center';
        ctx.fillText(n.label, n.x, n.y + n.r + 13);

        // Verified checkmark
        if (n.type === 'verified') {
          ctx.font = '9px system-ui';
          ctx.fillStyle = C.pohStart;
          ctx.globalAlpha = 0.9;
          ctx.fillText('✓', n.x, n.y + 3.5);
          ctx.globalAlpha = 1;
        }
      });

      ctx.restore();
      if (!REDUCED) requestAnimationFrame(draw);
    }

    window.addEventListener('resize', () => { resizeCanvas(canvas); draw(); });
    draw();
    if (!REDUCED) requestAnimationFrame(draw);
  })();

  // ══════════════════════════════════════════════════════════════
  // 5. STREAMING DRIP CANVAS (right panel of streaming section)
  //    Falling token drops visualizing the 1 UBI/hour flow
  // ══════════════════════════════════════════════════════════════
  (function initDripCanvas() {
    const canvas = document.getElementById('drip-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    let drops = [];
    let t = 0;

    function mkDrop(W) {
      return {
        x: W * (0.25 + Math.random() * 0.5),
        y: -12,
        vy: rand(1.2, 2.8),
        r: rand(2.5, 5),
        alpha: rand(0.5, 1),
        trail: [],
      };
    }

    function draw() {
      resizeCanvas(canvas);
      const dpr = getDPR();
      const W = canvas.width / dpr;
      const H = canvas.height / dpr;

      ctx.save();
      ctx.scale(dpr, dpr);

      // Fade background for trail effect
      ctx.fillStyle = 'rgba(6,6,10,0.18)';
      ctx.fillRect(0, 0, W, H);

      t += 1;

      // Spawn new drop every ~40 frames
      if (!REDUCED && t % 40 === 0 && drops.length < 14) {
        drops.push(mkDrop(W));
      }

      // Center column guide
      const cx = W / 2;
      const grad = ctx.createLinearGradient(cx, 0, cx, H);
      grad.addColorStop(0, 'rgba(79,231,168,0.06)');
      grad.addColorStop(0.5, 'rgba(79,231,168,0.12)');
      grad.addColorStop(1, 'rgba(79,231,168,0.02)');
      ctx.beginPath();
      ctx.rect(cx - 1, 0, 2, H);
      ctx.fillStyle = grad;
      ctx.fill();

      // Draw drops
      drops.forEach((d, i) => {
        d.y += d.vy;
        d.trail.push({ x: d.x, y: d.y });
        if (d.trail.length > 18) d.trail.shift();

        // Trail
        d.trail.forEach((pt, ti) => {
          const prog = ti / d.trail.length;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, d.r * prog * 0.6, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(79,231,168,${d.alpha * prog * 0.3})`;
          ctx.fill();
        });

        // Drop body
        const dropGrad = ctx.createRadialGradient(d.x, d.y, 0, d.x, d.y, d.r * 1.8);
        dropGrad.addColorStop(0, `rgba(79,231,168,${d.alpha * 0.9})`);
        dropGrad.addColorStop(0.6, `rgba(79,231,168,${d.alpha * 0.4})`);
        dropGrad.addColorStop(1, 'rgba(79,231,168,0)');
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r * 1.8, 0, Math.PI * 2);
        ctx.fillStyle = dropGrad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(160,255,220,${d.alpha})`;
        ctx.fill();

        // Remove if off screen
        if (d.y > H + 20) {
          drops.splice(i, 1);
        }
      });

      // Static illustration for reduced motion
      if (REDUCED) {
        for (let k = 0; k < 8; k++) {
          const ky = H * (0.1 + k * 0.11);
          const kx = W * (0.3 + (k % 3) * 0.2);
          ctx.beginPath();
          ctx.arc(kx, ky, 4, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(79,231,168,${0.3 + (k % 3) * 0.15})`;
          ctx.fill();
        }
      }

      ctx.restore();
      if (!REDUCED) requestAnimationFrame(draw);
    }

    // Seed initial drops
    if (!REDUCED) {
      drops = [mkDrop(100), mkDrop(100), mkDrop(100)];
      drops[0].y = 80;
      drops[1].y = 180;
      drops[2].y = 260;
    }

    window.addEventListener('resize', () => resizeCanvas(canvas));
    requestAnimationFrame(draw);
  })();

  // ══════════════════════════════════════════════════════════════
  // 6. FLOW ARROW CANVASES (streaming section mechanic diagram)
  // ══════════════════════════════════════════════════════════════
  (function initFlowArrows() {
    ['flow-arrow-canvas', 'flow-arrow-canvas-2'].forEach(id => {
      const canvas = document.getElementById(id);
      if (!canvas) return;

      const ctx = canvas.getContext('2d');
      let offset = 0;

      function draw() {
        resizeCanvas(canvas);
        const dpr = getDPR();
        const W = canvas.width / dpr;
        const H = canvas.height / dpr;

        ctx.save();
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, W, H);

        const cy = H / 2;
        // Animated dashed line
        ctx.setLineDash([8, 6]);
        ctx.lineDashOffset = REDUCED ? 0 : -offset;
        const lineGrad = ctx.createLinearGradient(0, 0, W, 0);
        lineGrad.addColorStop(0, 'rgba(79,231,168,0.15)');
        lineGrad.addColorStop(0.5, 'rgba(79,231,168,0.7)');
        lineGrad.addColorStop(1, 'rgba(79,231,168,0.15)');
        ctx.strokeStyle = lineGrad;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(4, cy);
        ctx.lineTo(W - 4, cy);
        ctx.stroke();

        // Arrowhead
        ctx.setLineDash([]);
        ctx.lineDashOffset = 0;
        ctx.beginPath();
        ctx.moveTo(W - 4, cy);
        ctx.lineTo(W - 12, cy - 4);
        ctx.moveTo(W - 4, cy);
        ctx.lineTo(W - 12, cy + 4);
        ctx.strokeStyle = 'rgba(79,231,168,0.7)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.restore();

        if (!REDUCED) {
          offset = (offset + 0.8) % 28;
          requestAnimationFrame(draw);
        }
      }

      window.addEventListener('resize', () => resizeCanvas(canvas));
      requestAnimationFrame(draw);
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 7. MINI NODE CANVAS (pillar cards in thesis section)
  // ══════════════════════════════════════════════════════════════
  (function initMiniCanvases() {
    // Mini drip for streaming pillar
    const dripMini = document.getElementById('drip-mini-1');
    if (dripMini) {
      const ctx = dripMini.getContext('2d');
      let offset = 0;

      function draw() {
        resizeCanvas(dripMini);
        const dpr = getDPR();
        const W = dripMini.width / dpr;
        const H = dripMini.height / dpr;
        ctx.save();
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, W, H);

        // Vertical drip line
        const cx = W / 2;
        if (!REDUCED) offset = (offset + 1) % (H * 2);

        for (let i = 0; i < 5; i++) {
          const y = ((offset + i * (H / 4)) % H);
          const alpha = 0.2 + (i % 3) * 0.25;
          ctx.beginPath();
          ctx.arc(cx, y, 3.5, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(79,231,168,${alpha})`;
          ctx.fill();
        }

        // Line
        ctx.strokeStyle = 'rgba(79,231,168,0.2)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(cx, 0); ctx.lineTo(cx, H);
        ctx.stroke();

        ctx.restore();
        if (!REDUCED) requestAnimationFrame(draw);
      }
      requestAnimationFrame(draw);
    }

    // Mini node mesh for network pillar
    const nodeMini = document.getElementById('node-mini-1');
    if (nodeMini) {
      const ctx = nodeMini.getContext('2d');
      const pts = [
        { x: 0.5, y: 0.2 }, { x: 0.15, y: 0.65 }, { x: 0.85, y: 0.65 },
        { x: 0.5, y: 0.85 }, { x: 0.2, y: 0.3 }, { x: 0.8, y: 0.3 },
      ];
      let t = 0;

      function draw() {
        resizeCanvas(nodeMini);
        const dpr = getDPR();
        const W = nodeMini.width / dpr;
        const H = nodeMini.height / dpr;
        ctx.save();
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, W, H);
        if (!REDUCED) t += 0.02;

        const nodes = pts.map((p, i) => ({
          x: p.x * W,
          y: p.y * H,
          pulse: 0.8 + 0.2 * Math.sin(t + i * 1.1),
        }));

        // Edges
        [[0,1],[0,2],[1,3],[2,3],[0,4],[0,5],[4,1],[5,2]].forEach(([a,b]) => {
          ctx.beginPath();
          ctx.moveTo(nodes[a].x, nodes[a].y);
          ctx.lineTo(nodes[b].x, nodes[b].y);
          ctx.strokeStyle = 'rgba(158,193,255,0.2)';
          ctx.lineWidth = 0.8;
          ctx.stroke();
        });

        // Nodes
        nodes.forEach((n, i) => {
          ctx.beginPath();
          ctx.arc(n.x, n.y, 3.5 * n.pulse, 0, Math.PI * 2);
          ctx.fillStyle = i < 4 ? `rgba(158,193,255,${0.7 * n.pulse})` : `rgba(139,123,255,${0.6 * n.pulse})`;
          ctx.fill();
        });

        ctx.restore();
        if (!REDUCED) requestAnimationFrame(draw);
      }
      requestAnimationFrame(draw);
    }
  })();

  // ══════════════════════════════════════════════════════════════
  // 8. NETWORK CANVAS (§6 — animated P2P node mesh + block flow)
  // ══════════════════════════════════════════════════════════════
  (function initNetworkCanvas() {
    const canvas = document.getElementById('network-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // 3 main validator nodes + satellite peers
    const VALIDATORS = [
      { id: 'A', cx: 0.22, cy: 0.50, label: 'Node A', isValidator: true },
      { id: 'B', cx: 0.50, cy: 0.20, label: 'Node B', isValidator: true },
      { id: 'C', cx: 0.78, cy: 0.50, label: 'Node C', isValidator: true },
      { id: 'd', cx: 0.15, cy: 0.82, label: 'Peer',   isValidator: false },
      { id: 'e', cx: 0.50, cy: 0.80, label: 'Peer',   isValidator: false },
      { id: 'f', cx: 0.85, cy: 0.82, label: 'Peer',   isValidator: false },
    ];

    const EDGES = [
      ['A','B'],['B','C'],['A','C'],
      ['A','d'],['A','e'],['B','e'],['C','f'],['C','e'],
    ];

    // Animated messages propagating along edges
    let messages = [];
    let blockCount = 1;
    let proposerIdx = 0;
    let t = 0;

    // Block counter for display
    const blockDisplay = document.getElementById('net-blocks');

    function spawnMessage(fromId, toId, type) {
      messages.push({ fromId, toId, type, progress: 0, speed: 0.008 + Math.random() * 0.006 });
    }

    function spawnBlock() {
      blockCount++;
      if (blockDisplay) blockDisplay.textContent = blockCount;
      proposerIdx = blockCount % 3;
      const proposer = VALIDATORS[proposerIdx];
      // Proposer broadcasts to all peers
      VALIDATORS.forEach(v => {
        if (v.id !== proposer.id) {
          setTimeout(() => {
            if (!REDUCED) spawnMessage(proposer.id, v.id, 'block');
          }, Math.random() * 400);
        }
      });
    }

    // Spawn a tx gossip every few seconds
    if (!REDUCED) {
      setInterval(() => {
        const from = VALIDATORS[randInt(3, 5)]; // from peer
        spawnMessage(from.id, 'A', 'tx');
        setTimeout(() => spawnMessage('A', 'B', 'tx'), 300);
        setTimeout(() => spawnMessage('A', 'C', 'tx'), 500);
      }, 3500);

      // Produce a block every 2 seconds (illustrative)
      setInterval(spawnBlock, 2000);
    }

    function draw() {
      resizeCanvas(canvas);
      const dpr = getDPR();
      const W = canvas.width / dpr;
      const H = canvas.height / dpr;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, W, H);

      if (!REDUCED) t += 0.015;

      const nodes = {};
      VALIDATORS.forEach(v => {
        nodes[v.id] = {
          ...v,
          x: v.cx * W,
          y: v.cy * H,
          r: v.isValidator ? 16 : 9,
          isProposer: v.isValidator && VALIDATORS.indexOf(v) === proposerIdx,
        };
      });

      // Edges
      EDGES.forEach(([ai, bi]) => {
        const a = nodes[ai], b = nodes[bi];
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = 'rgba(158,193,255,0.12)';
        ctx.lineWidth = 1;
        ctx.stroke();
      });

      // Animate messages
      messages.forEach((m, i) => {
        m.progress += m.speed;
        const a = nodes[m.fromId], b = nodes[m.toId];
        if (!a || !b) { messages.splice(i, 1); return; }
        const px = lerp(a.x, b.x, m.progress);
        const py = lerp(a.y, b.y, m.progress);
        const color = m.type === 'block' ? C.green : C.blue;
        const rp = m.type === 'block' ? 5 : 3;
        ctx.beginPath();
        ctx.arc(px, py, rp, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        // Glow
        ctx.beginPath();
        ctx.arc(px, py, rp * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = m.type === 'block' ? 'rgba(79,231,168,0.2)' : 'rgba(158,193,255,0.2)';
        ctx.fill();

        if (m.progress >= 1) messages.splice(i, 1);
      });

      // Draw nodes
      Object.values(nodes).forEach(n => {
        const pulse = REDUCED ? 1 : (0.88 + 0.12 * Math.sin(t + n.cx * 10));
        const color = n.isValidator
          ? (n.isProposer ? C.green : C.blue)
          : C.faint;

        // Glow ring for proposer
        if (n.isProposer && !REDUCED) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r + 8 + 4 * Math.sin(t * 3), 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(79,231,168,0.2)';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Outer ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = n.isValidator ? 1.5 : 1;
        ctx.globalAlpha = n.isValidator ? 0.7 : 0.35;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Core
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 0.55, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = n.isValidator ? 0.8 * pulse : 0.3;
        ctx.fill();
        ctx.globalAlpha = 1;

        // Label
        if (n.isValidator) {
          ctx.font = `700 11px system-ui`;
          ctx.fillStyle = n.isProposer ? C.green : C.blue;
          ctx.textAlign = 'center';
          ctx.fillText(n.label, n.x, n.y + n.r + 16);
          if (n.isProposer) {
            ctx.font = `600 9px system-ui`;
            ctx.fillStyle = C.green;
            ctx.fillText('▶ Proposer', n.x, n.y + n.r + 28);
          }
        }
      });

      ctx.restore();
      if (!REDUCED) requestAnimationFrame(draw);
    }

    window.addEventListener('resize', () => resizeCanvas(canvas));
    requestAnimationFrame(draw);
    if (!REDUCED) requestAnimationFrame(draw);
  })();

  // ══════════════════════════════════════════════════════════════
  // 9. INTERSECTION OBSERVER — scroll reveal
  //    We add .js-reveal to <body> first so CSS can target it.
  //    Without JS (headless Chrome, no-script) elements stay visible.
  // ══════════════════════════════════════════════════════════════
  (function initReveal() {
    if (REDUCED) {
      // Everything visible immediately — no animation class needed
      return;
    }

    // Activate the hidden-by-default state only when JS is running
    document.body.classList.add('js-reveal');

    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08 }
    );

    document.querySelectorAll('.reveal-section, .reveal-card').forEach(el => {
      observer.observe(el);
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 10. VIDEO SLOT HANDLING
  //     Hide video elements that have no loaded source so the
  //     canvas/gradient fallback shows. This keeps the layout
  //     clean until AI-generated clips are dropped in.
  // ══════════════════════════════════════════════════════════════
  (function initVideoSlots() {
    document.querySelectorAll('[data-video-slot]').forEach(video => {
      // Check if any <source> child has a real src
      const sources = video.querySelectorAll('source[src]');
      const hasSrc = video.getAttribute('src') ||
                     Array.from(sources).some(s => s.getAttribute('src') &&
                       !s.getAttribute('src').startsWith('<!--'));

      if (!hasSrc) {
        video.style.display = 'none';
        video.setAttribute('aria-hidden', 'true');
      } else {
        // Video present — show and fade in on canplay
        video.style.display = 'block';
        video.style.opacity = '0';
        video.style.transition = 'opacity 1s ease';
        video.addEventListener('canplay', () => {
          video.style.opacity = '1';
        }, { once: true });
      }
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 11. SMOOTH ANCHOR NAV with offset for sticky header
  // ══════════════════════════════════════════════════════════════
  (function initSmoothScroll() {
    if (REDUCED) return;
    document.querySelectorAll('a[href^="#"]').forEach(link => {
      link.addEventListener('click', e => {
        const id = link.getAttribute('href').slice(1);
        const target = document.getElementById(id);
        if (!target) return;
        e.preventDefault();
        const offset = 70; // nav height
        const y = target.getBoundingClientRect().top + window.scrollY - offset;
        window.scrollTo({ top: y, behavior: 'smooth' });
      });
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 12. ACTIVE NAV LINK — highlight on scroll
  // ══════════════════════════════════════════════════════════════
  (function initActiveNav() {
    const sections = ['hero','thesis','poh','streaming','contracts','network','evm','roadmap','run-node'];
    const links = {};
    sections.forEach(id => {
      const el = document.querySelector(`.nav-links a[href="#${id}"]`);
      if (el) links[id] = el;
    });

    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          Object.values(links).forEach(l => l.removeAttribute('aria-current'));
          const id = entry.target.id;
          if (links[id]) links[id].setAttribute('aria-current', 'page');
        }
      });
    }, { threshold: 0.35 });

    sections.forEach(id => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
  })();

  // ══════════════════════════════════════════════════════════════
  // 13. PARALLAX — subtle scroll parallax on hero canvas
  // ══════════════════════════════════════════════════════════════
  (function initParallax() {
    if (REDUCED) return;
    const canvas = document.getElementById('hero-canvas');
    if (!canvas) return;

    let lastScroll = 0;
    window.addEventListener('scroll', () => {
      const scroll = window.scrollY;
      const delta = scroll - lastScroll;
      lastScroll = scroll;
      // Gentle parallax on canvas via transform
      canvas.style.transform = `translateY(${scroll * 0.25}px)`;
    }, { passive: true });
  })();

})();
