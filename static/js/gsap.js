document.addEventListener('DOMContentLoaded', function() {
    const images = document.querySelectorAll('#image-slider .slider-image');
    const layout = document.querySelector('section'); // Select the layout section
    let currentIndex = 0;

    // Blinking light effect function
    function blinkLight() {
        const light = document.createElement('div');
        light.style.position = 'fixed';  // Make sure it's fixed so it stays in the same position
        light.style.width = '100px';     // Increase the size to make it more noticeable
        light.style.height = '100px';    // Match width with height
        light.style.background = 'radial-gradient(circle, rgba(255,255,255,1) 0%, rgba(255,255,255,0) 100%)'; // White radial light
        light.style.borderRadius = '50%';
        light.style.zIndex = '9999';     // Ensure it's above all other elements
        light.style.pointerEvents = 'none'; // Prevent it from interfering with clicks
        light.style.top = '50%';
        light.style.left = '50%';
        light.style.transform = 'translate(-50%, -50%)';
        light.style.animation = 'blink-animation 0.6s ease-out';
        document.body.appendChild(light);

        // Remove the light after the animation finishes
        setTimeout(() => {
            light.remove();
        }, 600); // Match this with the animation duration
    }

    // GSAP fade in/out function
    function fadeInOutImages() {
        const currentImage = images[currentIndex];
        const nextIndex = (currentIndex + 1) % images.length; // Loop back to the first image
        const nextImage = images[nextIndex];

        // Background color change with GSAP
        gsap.to(layout, { 
            duration: 2, 
            background: getRandomBackgroundGradient(), 
            ease: "power2.inOut" 
        });

        // Blink effect before transition
        blinkLight();

        // Fade out the current image
        gsap.to(currentImage, { duration: 1, opacity: 0, ease: "power2.inOut" });

        // Fade in the next image
        gsap.to(nextImage, { duration: 1, opacity: 1, ease: "power2.inOut", onComplete: function() {
            currentIndex = nextIndex; // Update the index after animation completes
        }});

        // Schedule the next transition
        setTimeout(fadeInOutImages, 3000); // Change image every 3 seconds
    }

    // Generate random gradient backgrounds for layout
    function getRandomBackgroundGradient() {
        const gradients = [
            'radial-gradient(circle, rgba(255,123,123,0.2) 0%, rgba(123,255,255,0.15) 40%, rgba(123,123,255,0.05) 70%, transparent 100%)',
            'radial-gradient(circle, rgba(123,255,200,0.2) 0%, rgba(200,255,123,0.15) 40%, rgba(255,123,123,0.05) 70%, transparent 100%)',
            'radial-gradient(circle, rgba(200,123,255,0.2) 0%, rgba(255,255,123,0.15) 40%, rgba(123,255,123,0.05) 70%, transparent 100%)',
        ];
        return gradients[Math.floor(Math.random() * gradients.length)];
    }

    // Initialize the slider
    gsap.set(images[0], { opacity: 1 }); // Show the first image
    setTimeout(fadeInOutImages, 3000);   // Start the image slider after 3 seconds

    // Blinking light keyframes
    const styleSheet = document.createElement("style");
    styleSheet.innerHTML = `
        @keyframes blink-animation {
            0% { transform: translate(-50%, -50%) scale(0); opacity: 1; }
            100% { transform: translate(-50%, -50%) scale(1.5); opacity: 0; }
        }
    `;
    document.head.appendChild(styleSheet);
});
