document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan-form');
    const spinner = document.getElementById('loading-spinner');
    const btnText = document.getElementById('btn-text');
    const submitBtn = document.getElementById('submit-btn');
    const alertBox = document.getElementById('alert-box');
    const resultBox = document.getElementById('result-box');

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        // Reset messages
        alertBox.innerHTML = '';
        resultBox.style.display = 'none';
        // Show spinner
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Scanning...';
        submitBtn.disabled = true;

        const type = document.getElementById('inputType').value;
        const input = document.getElementById('inputValue').value.trim();

        if (!input) {
            spinner.style.display = 'none';
            btnText.textContent = 'Scan';
            submitBtn.disabled = false;
            alertBox.innerHTML = `<div class="alert alert-danger">Input cannot be empty.</div>`;
            return;
        }

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type, input })
            });
            const data = await response.json();
            spinner.style.display = 'none';
            btnText.textContent = 'Scan';
            submitBtn.disabled = false;

            if (data.success) {
                let alertClass = 'alert-success';
                if (data.result === 'Phishing') alertClass = 'alert-danger';
                else if (data.result === 'Suspicious') alertClass = 'alert-warning';

                resultBox.className = `alert ${alertClass} mt-4`;
                resultBox.innerHTML = `
                    <h5>Result: ${data.result}</h5>
                    <p>Confidence: ${data.confidence}%</p>
                    ${data.threats_detected && data.threats_detected.length ? 
                        `<ul>${data.threats_detected.map(t => `<li>${t}</li>`).join('')}</ul>` : ''}
                `;
                resultBox.style.display = 'block';
            } else {
                alertBox.innerHTML = `<div class="alert alert-danger">${data.error || 'Scan failed.'}</div>`;
            }
        } catch (err) {
            spinner.style.display = 'none';
            btnText.textContent = 'Scan';
            submitBtn.disabled = false;
            alertBox.innerHTML = `<div class="alert alert-danger">Network error. Please try again.</div>`;
        }
    });
});
