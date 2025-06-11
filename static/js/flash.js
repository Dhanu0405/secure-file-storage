document.addEventListener("DOMContentLoaded", () => {
  const flash = document.getElementById("flash-container");
  if (flash) {
    setTimeout(() => {
      flash.style.transition = "opacity 0.5s ease-out";
      flash.style.opacity = "0";
      setTimeout(() => flash.remove(), 500); // Remove after fade out
    }, 3000); // Flash disappears after 3 seconds
  }
});