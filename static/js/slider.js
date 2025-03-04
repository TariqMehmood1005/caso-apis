class ImageSlider {
    constructor(sliderSelector, layoutSelector, isBlinkAnimationSelector = true) {
        this.images = document.querySelectorAll(`${sliderSelector} .slider-image`);
        this.layout = document.querySelector(layoutSelector) || document.body;
        this.isBlinkAnimationSelector = isBlinkAnimationSelector;
        this.currentIndex = 0;

        // Show the first image
        gsap.set(this.images[0], { opacity: 1 });

        this.init();
    }

    init() {
        this.createBlinkKeyframes();
        setTimeout(() => this.fadeInOutImages(), 3000);
    }

    createBlinkKeyframes() {
        const styleSheet = document.createElement("style");
        styleSheet.innerHTML = `
            @keyframes blink-animation {
                0% { transform: translate(-50%, -50%) scale(0); opacity: 1; }
                100% { transform: translate(-50%, -50%) scale(1.2); opacity: 0; }
            }
        `;
        document.head.appendChild(styleSheet);
    }

    getRandomRadialGradient() {
        const gradients = [
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(0, 153, 255, 0.8) 40%, rgba(0, 153, 255, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(255, 94, 98, 0.8) 40%, rgba(255, 94, 98, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(102, 255, 178, 0.8) 40%, rgba(102, 255, 178, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(255, 206, 84, 0.8) 40%, rgba(255, 206, 84, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(153, 102, 255, 0.8) 40%, rgba(153, 102, 255, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(94, 184, 255, 0.8) 40%, rgba(94, 184, 255, 0) 70%)',
            'radial-gradient(circle, rgba(255, 255, 255, 1) 0%, rgba(255, 153, 204, 0.8) 40%, rgba(255, 153, 204, 0) 70%)'
        ];
        return gradients[Math.floor(Math.random() * gradients.length)];
    }

    getRandomBackgroundGradient() {
        const gradients = [
            'radial-gradient(circle, rgba(255,123,123,0.2) 0%, rgba(123,255,255,0.15) 40%, rgba(123,123,255,0.05) 70%, transparent 100%)',
            'radial-gradient(circle, rgba(123,255,200,0.2) 0%, rgba(200,255,123,0.15) 40%, rgba(255,123,123,0.05) 70%, transparent 100%)',
            'radial-gradient(circle, rgba(200,123,255,0.2) 0%, rgba(255,255,123,0.15) 40%, rgba(123,255,123,0.05) 70%, transparent 100%)'
        ];
        return gradients[Math.floor(Math.random() * gradients.length)];
    }

    blinkLight() {
        if (!this.isBlinkAnimationSelector) return;

        const light = document.createElement('div');
        const diameter = Math.min(this.layout.offsetWidth, this.layout.offsetHeight);
    
        light.style.position = 'absolute';
        light.style.width = `${diameter}px`;
        light.style.height = `${diameter}px`;
        light.style.borderRadius = '50%';
        light.style.zIndex = '9999';
        light.style.pointerEvents = 'none';
        light.style.top = '50%';
        light.style.left = '50%';
        light.style.transform = 'translate(-50%, -50%)';
        light.style.animation = 'blink-animation 0.6s ease-out';
        light.style.background = this.getRandomRadialGradient();
    
        this.layout.appendChild(light);
        setTimeout(() => light.remove(), 600);
    }

    fadeInOutImages() {
        const currentImage = this.images[this.currentIndex];
        const nextIndex = (this.currentIndex + 1) % this.images.length;
        const nextImage = this.images[nextIndex];

        if (this.isBlinkAnimationSelector) {
            gsap.to(this.layout, {
                duration: 2,
                background: this.getRandomBackgroundGradient(),
                ease: "power2.inOut"
            });
        }

        this.blinkLight();

        gsap.to(currentImage, { duration: 1, opacity: 0, ease: "power2.inOut" });
        gsap.to(nextImage, {
            duration: 1,
            opacity: 1,
            ease: "power2.inOut",
            onComplete: () => {
                this.currentIndex = nextIndex;
            }
        });

        setTimeout(() => this.fadeInOutImages(), 3000);
    }
}
