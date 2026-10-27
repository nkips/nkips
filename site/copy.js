// Copy a link to the section (or requirement) whose anchor was clicked.
// Without JS the anchors still work: they jump to the section and update the URL.
(function () {
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a.anchor');
    if (!a || !navigator.clipboard) return;
    e.preventDefault();
    var url = location.origin + location.pathname + a.getAttribute('href');
    history.replaceState(null, '', a.getAttribute('href'));
    var target = document.getElementById(a.getAttribute('href').slice(1));
    if (target) target.scrollIntoView({ block: 'start' });
    navigator.clipboard.writeText(url).then(function () {
      a.classList.add('copied');
      setTimeout(function () { a.classList.remove('copied'); }, 1400);
    }, function () {});
  });
})();
