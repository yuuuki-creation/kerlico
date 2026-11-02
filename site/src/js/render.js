// 形变和明暗都在 JS 里算完，两个栅格化层只负责把 [x, y, r, g, b] 画出来，退回 canvas 时画面一致。
const FLOATS = 5;

function createGlRenderer(canvas) {
  const gl = canvas.getContext('webgl', { antialias: true, alpha: false, powerPreference: 'low-power' });
  if (!gl) return null;
  const compile = (type, source) => {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    return shader;
  };
  let locRes, buffer;
  const setup = () => {
    const program = gl.createProgram();
    gl.attachShader(program, compile(gl.VERTEX_SHADER,
      'attribute vec2 p;attribute vec3 c;uniform vec2 r;varying vec3 v;void main(){v=c;gl_Position=vec4(p.x/r.x*2.-1.,1.-p.y/r.y*2.,0.,1.);}'));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER,
      'precision mediump float;varying vec3 v;void main(){gl_FragColor=vec4(v,1.);}'));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return false;
    gl.useProgram(program);
    locRes = gl.getUniformLocation(program, 'r');
    buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    const locP = gl.getAttribLocation(program, 'p');
    const locC = gl.getAttribLocation(program, 'c');
    gl.enableVertexAttribArray(locP);
    gl.enableVertexAttribArray(locC);
    gl.vertexAttribPointer(locP, 2, gl.FLOAT, false, FLOATS * 4, 0);
    gl.vertexAttribPointer(locC, 3, gl.FLOAT, false, FLOATS * 4, 8);
    return true;
  };
  if (!setup()) return null;
  let lost = false;
  canvas.addEventListener('webglcontextlost', (event) => {
    event.preventDefault();
    lost = true;
  });
  canvas.addEventListener('webglcontextrestored', () => {
    lost = !setup();
  });
  return {
    kind: 'GL',
    resize(w, h, dpr) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(locRes, w, h);
    },
    draw(field, word) {
      if (lost) return;
      gl.clearColor(INK[0], INK[1], INK[2], 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      const pass = (mode, data, count) => {
        if (!count) return;
        gl.bufferData(gl.ARRAY_BUFFER, data.subarray(0, count * FLOATS), gl.DYNAMIC_DRAW);
        gl.drawArrays(mode, 0, count);
      };
      pass(gl.TRIANGLES, field.triBuf, field.triCount);
      pass(gl.LINES, field.lineBuf, field.lineCount);
      pass(gl.TRIANGLES, word.buf, word.count);
    },
  };
}

function createCanvasRenderer(canvas) {
  const ctx = canvas.getContext('2d', { alpha: false });
  if (!ctx) return null;
  const css = (v) => Math.round(clamp(v, 0, 1) * 255);
  let width = 0, height = 0;
  const fills = (data, count) => {
    for (let i = 0; i < count; i += 3) {
      const b = i * FLOATS;
      const color = `rgb(${css(data[b + 2])},${css(data[b + 3])},${css(data[b + 4])})`;
      ctx.fillStyle = color;
      ctx.strokeStyle = color;
      ctx.beginPath();
      ctx.moveTo(data[b], data[b + 1]);
      ctx.lineTo(data[b + 5], data[b + 6]);
      ctx.lineTo(data[b + 10], data[b + 11]);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  };
  return {
    kind: '2D',
    resize(w, h, dpr) {
      width = w;
      height = h;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.lineWidth = 0.7;
      ctx.lineJoin = 'round';
    },
    draw(field, word) {
      ctx.fillStyle = '#10131C';
      ctx.fillRect(0, 0, width, height);
      fills(field.triBuf, field.triCount);
      for (let i = 0; i < field.lineCount; i += 2) {
        const b = i * FLOATS;
        const d = field.lineBuf;
        ctx.strokeStyle = `rgb(${css(d[b + 2])},${css(d[b + 3])},${css(d[b + 4])})`;
        ctx.beginPath();
        ctx.moveTo(d[b], d[b + 1]);
        ctx.lineTo(d[b + 5], d[b + 6]);
        ctx.stroke();
      }
      fills(word.buf, word.count);
    },
  };
}

function createRenderer(canvas) {
  const forced2d = /[?&]renderer=2d\b/.test(location.search);
  return (!forced2d && createGlRenderer(canvas)) || createCanvasRenderer(canvas);
}
