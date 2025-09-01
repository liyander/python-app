document.addEventListener('DOMContentLoaded', function() {
    // Create custom cursor elements
    const cursorDot = document.createElement('div');
    const cursorOutline = document.createElement('div');
    cursorDot.classList.add('cursor-dot');
    cursorOutline.classList.add('cursor-outline');
    document.body.appendChild(cursorDot);
    document.body.appendChild(cursorOutline);

    // Dynamic background effect with custom cursor
    document.addEventListener('mousemove', function(e) {
        const x = e.clientX;
        const y = e.clientY;
        const body = document.body;
        
        // Update cursor position with smooth animation
        requestAnimationFrame(() => {
            cursorDot.style.left = (x - 4) + 'px';
            cursorDot.style.top = (y - 4) + 'px';
            cursorOutline.style.left = (x - 17.5) + 'px';
            cursorOutline.style.top = (y - 17.5) + 'px';
        });
        
        // Create dynamic background with multiple gradients
        const centerX = window.innerWidth / 2;
        const centerY = window.innerHeight / 2;
        const distanceFromCenter = Math.sqrt(Math.pow(x - centerX, 2) + Math.pow(y - centerY, 2));
        const maxDistance = Math.sqrt(Math.pow(centerX, 2) + Math.pow(centerY, 2));
        const intensity = 1 - (distanceFromCenter / maxDistance);
        
        const isDark = body.getAttribute('data-theme') === 'dark';
        const baseGradient = isDark 
            ? 'linear-gradient(135deg, #000000 0%, #1a1a1a 100%)'
            : 'linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%)';
        
        body.style.background = `
            radial-gradient(circle 600px at ${x}px ${y}px, rgba(255, 215, 0, ${0.08 * intensity}) 0%, transparent 40%),
            radial-gradient(circle 400px at ${x + 100}px ${y - 100}px, rgba(255, 235, 59, ${0.06 * intensity}) 0%, transparent 50%),
            radial-gradient(circle 300px at ${x - 100}px ${y + 100}px, rgba(255, 193, 7, ${0.04 * intensity}) 0%, transparent 50%),
            ${baseGradient}
        `;
    });

    // Dark mode functionality
    const darkModeSwitch = document.getElementById('dark-mode-switch');
    const body = document.body;
    
    // Check for saved dark mode preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        body.setAttribute('data-theme', savedTheme);
        darkModeSwitch.checked = savedTheme === 'dark';
    }
    
    darkModeSwitch.addEventListener('change', function() {
        if (this.checked) {
            body.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
        } else {
            body.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
        }
        
        // Add a subtle animation when switching themes
        body.style.transform = 'scale(0.98)';
        setTimeout(() => {
            body.style.transform = 'scale(1)';
        }, 200);
    });

    // Tab functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.dataset.tab;
            const currentActive = document.querySelector('.tab-content.active');
            const targetContent = document.getElementById(`${targetTab}-tab`);
            
            // Don't do anything if clicking the same tab
            if (btn.classList.contains('active')) return;
            
            // Remove active class from all tabs
            tabBtns.forEach(b => b.classList.remove('active'));
            
            // Enhanced slide transition effect
            if (currentActive) {
                // Add slide-out class
                currentActive.classList.add('slide-out-left');
                
                // Add a ripple effect to the clicked tab
                const ripple = document.createElement('div');
                ripple.style.cssText = `
                    position: absolute;
                    background: rgba(255, 215, 0, 0.3);
                    border-radius: 50%;
                    transform: scale(0);
                    animation: ripple 0.6s ease-out;
                    pointer-events: none;
                    top: 50%;
                    left: 50%;
                    width: 100px;
                    height: 100px;
                    margin-left: -50px;
                    margin-top: -50px;
                `;
                
                btn.style.position = 'relative';
                btn.appendChild(ripple);
                
                setTimeout(() => {
                    if (ripple.parentNode) {
                        ripple.parentNode.removeChild(ripple);
                    }
                }, 600);
                
                setTimeout(() => {
                    currentActive.classList.remove('active', 'slide-out-left');
                    currentActive.style.display = 'none';
                    
                    // Add active class to clicked tab
                    btn.classList.add('active');
                    
                    // Show and animate in new content
                    targetContent.style.display = 'block';
                    targetContent.classList.add('slide-in-right');
                    
                    setTimeout(() => {
                        targetContent.classList.add('active');
                        targetContent.classList.remove('slide-in-right');
                    }, 50);
                }, 300);
            } else {
                // If no current active (initial load)
                btn.classList.add('active');
                targetContent.classList.add('active');
            }
            
            // Clear any previous errors
            clearErrors();
        });
    });
    
    // Form submission
    const form = document.getElementById('phishing-form');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const results = document.getElementById('results');
    
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Clear previous errors and results
        clearErrors();
        results.classList.remove('show');
        
        // Get active tab and input
        const activeTab = document.querySelector('.tab-btn.active').dataset.tab;
        const input = document.getElementById(`${activeTab}-input`);
        const value = input.value.trim();
        
        // Validate input
        if (!validateInput(activeTab, value)) {
            return;
        }
        
        // Show loading state
        setLoadingState(true);
        
        try {
            // Send scan request to backend
            console.log('Sending scan request:', {
                type: activeTab,
                value: value
            });
            
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    type: activeTab,
                    value: value
                })
            });
            
            console.log('Scan response status:', response.status);
            console.log('Scan response headers:', response.headers);
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Scan request failed: ${response.status} - ${errorText}`);
            }
            
            const result = await response.json();
            console.log('Scan result:', result);
            
            // Validate response structure
            if (!result || typeof result.is_safe === 'undefined') {
                throw new Error('Invalid response format from server');
            }
            
            displayResult(result);
            
        } catch (error) {
            console.error('Error:', error);
            showError('general', `An error occurred while analyzing: ${error.message}. Please try again.`);
        } finally {
            setLoadingState(false);
        }
    });
    
    // Input validation functions
    function validateInput(type, value) {
        if (!value) {
            showError(type, 'This field is required');
            return false;
        }
        
        if (type === 'url') {
            return validateURL(value);
        } else if (type === 'email') {
            return validateEmail(value);
        }
        
        return true;
    }
    
    function validateURL(url) {
        // Check if URL is valid
        try {
            new URL(url);
        } catch {
            showError('url', 'Please enter a valid URL (e.g., https://example.com)');
            return false;
        }
        
        // Check if URL has protocol
        if (!url.match(/^https?:\/\//i)) {
            showError('url', 'URL must start with http:// or https://');
            return false;
        }
        
        return true;
    }
    
    function validateEmail(email) {
        if (email.length < 5) {
            showError('email', 'Email content seems too short. Please provide more content to analyze.');
            return false;
        }
        
        return true;
    }
    
    function showError(type, message) {
        if (type === 'general') {
            // Show general error in results area
            const results = document.getElementById('results');
            results.className = 'results show danger';
            document.getElementById('result-title').textContent = '❌ Error';
            document.getElementById('result-message').textContent = message;
            document.getElementById('result-details').innerHTML = '';
            document.getElementById('confidence-badge').textContent = '';
            results.scrollIntoView({ behavior: 'smooth' });
            return;
        }
        
        const input = document.getElementById(`${type}-input`);
        const errorElement = document.getElementById(`${type}-error`);
        
        if (input) input.classList.add('error');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.add('show');
        }
    }
    
    function clearErrors() {
        const inputs = document.querySelectorAll('input, textarea');
        const errors = document.querySelectorAll('.error-message');
        
        inputs.forEach(input => input.classList.remove('error'));
        errors.forEach(error => {
            error.classList.remove('show');
            error.textContent = '';
        });
    }
    
    function setLoadingState(loading) {
        submitBtn.disabled = loading;
        if (loading) {
            btnText.textContent = 'Analyzing...';
            spinner.style.display = 'block';
        } else {
            btnText.textContent = 'Analyze';
            spinner.style.display = 'none';
        }
    }
    
    function displayResult(result) {
        const resultTitle = document.getElementById('result-title');
        const resultMessage = document.getElementById('result-message');
        const resultDetails = document.getElementById('result-details');
        const confidenceBadge = document.getElementById('confidence-badge');
        
        // First hide the results if they're showing
        if (results.classList.contains('show')) {
            results.style.opacity = '0';
            results.style.transform = 'translateY(20px) scale(0.95)';
            
            setTimeout(() => {
                updateResultContent();
                animateResultsIn();
            }, 300);
        } else {
            updateResultContent();
            animateResultsIn();
        }
        
        function updateResultContent() {
            // Set result class based on safety
            results.className = 'results ' + (result.is_safe ? 'safe' : 'danger');
            
            // Update content
            resultTitle.textContent = result.is_safe ? '✅ Safe' : '⚠️ Suspicious';
            resultMessage.textContent = result.message;
            confidenceBadge.textContent = `${result.confidence}% confidence`;
            
            // Update details with staggered animation
            resultDetails.innerHTML = '';
            result.details.forEach((detail, index) => {
                const li = document.createElement('li');
                li.textContent = detail;
                li.style.opacity = '0';
                li.style.transform = 'translateX(-20px)';
                li.style.transition = `all 0.3s ease ${index * 0.1}s`;
                resultDetails.appendChild(li);
                
                // Animate in each detail item
                setTimeout(() => {
                    li.style.opacity = '1';
                    li.style.transform = 'translateX(0)';
                }, 50);
            });
        }
        
        function animateResultsIn() {
            results.classList.add('show');
            
            // Scroll to results with smooth animation
            setTimeout(() => {
                results.scrollIntoView({ 
                    behavior: 'smooth',
                    block: 'nearest'
                });
            }, 200);
        }
    }
    
    // Real-time input validation
    document.getElementById('url-input').addEventListener('input', function() {
        if (this.classList.contains('error')) {
            this.classList.remove('error');
            document.getElementById('url-error').classList.remove('show');
        }
    });
    
    document.getElementById('email-input').addEventListener('input', function() {
        if (this.classList.contains('error')) {
            this.classList.remove('error');
            document.getElementById('email-error').classList.remove('show');
        }
    });

    // Add hover effects for interactive elements
    const interactiveElements = document.querySelectorAll('button, input, textarea, .tab-btn, .dark-mode-switch');
    
    interactiveElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            cursorDot.style.transform = 'scale(1.5)';
            cursorOutline.style.transform = 'scale(1.3)';
        });
        
        element.addEventListener('mouseleave', function() {
            cursorDot.style.transform = 'scale(1)';
            cursorOutline.style.transform = 'scale(1)';
        });
    });

    // Add click effects
    document.addEventListener('mousedown', function() {
        cursorDot.style.transform = 'scale(0.8)';
        cursorOutline.style.transform = 'scale(0.7)';
    });

    document.addEventListener('mouseup', function() {
        cursorDot.style.transform = 'scale(1)';
        cursorOutline.style.transform = 'scale(1)';
    });

    // Hide cursor when leaving window
    document.addEventListener('mouseleave', function() {
        cursorDot.style.opacity = '0';
        cursorOutline.style.opacity = '0';
    });

    document.addEventListener('mouseenter', function() {
        cursorDot.style.opacity = '1';
        cursorOutline.style.opacity = '1';
    });
});