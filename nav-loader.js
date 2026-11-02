/* Top navigation progress bar for real page-to-page navigation.
   Old page: starts on the click and crawls towards 90% while the browser fetches the next document (no fixed delay).
   New page: resumes from where the old page stopped (sessionStorage hint, max 10 s old) and completes when the first render is done. */
(function () {
  var KEY = 'site_nav_progress', bar = document.querySelector('.nl'); if (!bar) return;
  var fill = bar.firstElementChild, p = 0, raf = 0, running = false, guard = 0;
  function set(v) { p = v; fill.style.transform = 'scaleX(' + v + ')'; }
  function loop() { if (!running) return; set(p + Math.max((0.9 - p) * 0.045, 0.0006)); raf = requestAnimationFrame(loop); }
  function begin(from) {
    if (running) return; running = true; bar.classList.remove('fin'); bar.classList.add('on'); set(from); cancelAnimationFrame(raf); raf = requestAnimationFrame(loop);
    clearTimeout(guard); guard = setTimeout(done, 12000); /* never leave the bar stuck (cancelled navigation, download link...) */
  }
  function start() { try { sessionStorage.setItem(KEY, JSON.stringify({ t: Date.now(), p: 0.1 })); } catch (e) { /* ignore */ } begin(0.08); }
  function done() {
    clearTimeout(guard); try { sessionStorage.removeItem(KEY); } catch (e) { /* ignore */ }
    if (!running && !bar.classList.contains('on')) return;
    running = false; cancelAnimationFrame(raf); bar.classList.add('fin'); set(1);
    setTimeout(function () { bar.classList.remove('on'); setTimeout(function () { bar.classList.remove('fin'); set(0); }, 300); }, 160);
  }
  function reset() { running = false; clearTimeout(guard); cancelAnimationFrame(raf); bar.classList.remove('on', 'fin'); set(0); try { sessionStorage.removeItem(KEY); } catch (e) { /* ignore */ } }
  window.addEventListener('pagehide', function () { if (running) { try { sessionStorage.setItem(KEY, JSON.stringify({ t: Date.now(), p: p })); } catch (e) { /* ignore */ } } });
  window.__NAVLOAD__ = { start: start, done: done, reset: reset };
  try {
    var st = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (st && Date.now() - st.t < 10000) begin(Math.min(0.9, Math.max(0.2, st.p || 0.3))); else sessionStorage.removeItem(KEY);
  } catch (e) { /* ignore */ }
})();
