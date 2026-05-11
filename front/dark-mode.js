/* dark-mode.js — APKInsight
   <head> 최상단에 로드 → FOUC 방지 + 토글 함수 제공 */

// FOUC 방지: 스크립트 파싱 즉시 실행
(function () {
  try {
    if (localStorage.getItem('apkinsight_theme') === 'dark') {
      document.documentElement.classList.add('dark-mode');
    }
  } catch (e) {}
})();

function _swapLogo(isDark) {
  document.querySelectorAll('img[src="apkinsight.png"], img[src="apkinsight_dark.png"]').forEach(function(img) {
    img.src = isDark ? 'apkinsight_dark.png' : 'apkinsight.png';
  });
}

document.addEventListener('DOMContentLoaded', function() {
  _swapLogo(document.documentElement.classList.contains('dark-mode'));
});

function toggleDarkMode() {
  const isDark = document.documentElement.classList.toggle('dark-mode');
  try {
    localStorage.setItem('apkinsight_theme', isDark ? 'dark' : 'light');
  } catch (e) {}
  _swapLogo(isDark);
}
