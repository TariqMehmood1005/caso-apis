document.addEventListener("DOMContentLoaded", function () {
    const forgotPasswordLink = document.getElementById("forgot-password-link");
    const loginModal = document.getElementById("login-modal");
    const newPasswordModal = document.getElementById("create-a-new-password-modal");
    const closeModalButtons = document.querySelectorAll("[data-modal-hide]");
    const backToLoginButton = document.getElementById("back-to-login");
    const cancelButton = document.getElementById("cancel");

    // GSAP animation to show a modal
    function showModal(modal) {
        console.log("Showing modal:", modal.id); // Debugging
        modal.style.display = 'flex'; // Ensure it's visible before animation
        gsap.to(modal, {
            duration: 0.5,
            opacity: 1,
            scale: 1,
            ease: "power2.inOut",
        });
    }

    // GSAP animation to hide a modal
    function hideModal(modal) {
        console.log("Hiding modal:", modal.id); // Debugging
        gsap.to(modal, {
            duration: 0.5,
            opacity: 0,
            scale: 0.8,
            ease: "power2.inOut",
            onComplete: function() {
                modal.style.display = 'none'; // Hide after animation
                console.log("Modal hidden:", modal.id); // Debugging
            }
        });
    }

    // Handle forgot password click
    forgotPasswordLink.addEventListener("click", function (event) {
        event.preventDefault();
        hideModal(loginModal);
        setTimeout(() => showModal(newPasswordModal), 500); // Delayed showing to ensure proper hiding
    });

    // Handle back to login from create new password modal
    backToLoginButton.addEventListener("click", function () {
        hideModal(newPasswordModal);
        setTimeout(() => showModal(loginModal), 500); // Delayed showing to ensure proper hiding
    });

    // Cancel back to login from create new password modal
    cancelButton.addEventListener("click", function () {
        hideModal(newPasswordModal);
        setTimeout(() => showModal(loginModal), 500); // Delayed showing to ensure proper hiding
    });

    // Handle close modal
    closeModalButtons.forEach(button => {
        button.addEventListener("click", function () {
            console.log("Closing all modals"); // Debugging
            hideModal(loginModal);
            hideModal(newPasswordModal);
        });
    });
});
