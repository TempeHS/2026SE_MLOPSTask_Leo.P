if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker
      .register("static/js/serviceWorker.js")
      .then((res) => console.log("service worker registered"))
      .catch((err) => console.log("service worker not registered", err));
  });
}

// Online/Offline detection
const offlineBanner = document.getElementById("offline-banner");

function updateOnlineStatus() {
  if (navigator.onLine) {
    // User is online
    offlineBanner.style.display = "none";
    console.log("App is online");
  } else {
    // User is offline
    offlineBanner.style.display = "block";
    console.log("App is offline");
  }
}

// Check status when page loads
window.addEventListener("load", updateOnlineStatus);

// Listen for online event
window.addEventListener("online", function () {
  updateOnlineStatus();
  console.log("Connection restored");
});

// Listen for offline event
window.addEventListener("offline", function () {
  updateOnlineStatus();
  console.log("Connection lost");
});

// This script toggles the active class and aria-current attribute on the nav links
document.addEventListener("DOMContentLoaded", function () {
  const navLinks = document.querySelectorAll(".nav-link");
  const currentUrl = window.location.pathname;

  navLinks.forEach((link) => {
    const linkUrl = link.getAttribute("href");
    if (linkUrl === currentUrl) {
      link.classList.add("active");
      link.setAttribute("aria-current", "page");
    } else {
      link.classList.remove("active");
      link.removeAttribute("aria-current");
    }
  });
});

// PWA Installation
let deferredPrompt;
const installButton = document.getElementById("install-button");

// Capture the install prompt event
window.addEventListener("beforeinstallprompt", (event) => {
  // Prevent the default browser install prompt
  event.preventDefault();

  // Store the event so we can trigger it later
  deferredPrompt = event;

  // Show our custom install button
  installButton.style.display = "block";

  console.log("App is installable - showing install button");
});

// Handle install button click
installButton.addEventListener("click", async () => {
  if (!deferredPrompt) {
    console.log("Install prompt not available");
    return;
  }

  // Show the install prompt
  deferredPrompt.prompt();

  // Wait for the user's response
  const { outcome } = await deferredPrompt.userChoice;

  console.log(`User response: ${outcome}`);

  if (outcome === "accepted") {
    console.log("User accepted the install prompt");
  } else {
    console.log("User dismissed the install prompt");
  }

  // Clear the deferred prompt
  deferredPrompt = null;

  // Hide the install button
  installButton.style.display = "none";
});

// Detect when app is successfully installed
window.addEventListener("appinstalled", () => {
  console.log("PWA was installed successfully");

  // Hide install button (app is now installed)
  installButton.style.display = "none";

  // Clear the deferred prompt
  deferredPrompt = null;
});
