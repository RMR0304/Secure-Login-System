/**
 * Secure Campus Portal - Client Logic
 * Handles interactive password policy validation, visibility toggles,
 * and asynchronous authentication flows.
 */

document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles();
    initUrlFeedback();
    initLoginForm();
    initRegisterForm();
    initChangePasswordForm();
    initRecoveryFlow();
});

/* --- Password Visibility Toggle --- */
function initPasswordToggles() {
    document.querySelectorAll('.pwd-toggle').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const isPassword = input.getAttribute('type') === 'password';
            input.setAttribute('type', isPassword ? 'text' : 'password');

            // Update SVG icon representation
            btn.innerHTML = isPassword
                ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
                : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
        });
    });
}

/* --- Feedback from Query Parameters --- */
function initUrlFeedback() {
    const params = new URLSearchParams(window.location.search);
    const alertBox = document.getElementById('login-alert');
    if (!alertBox) return;

    if (params.has('logged_out')) {
        showAlert(alertBox, 'Your session has been securely terminated.', 'success');
    } else if (params.has('unauthorized')) {
        showAlert(alertBox, 'Authentication required to access protected campus portal views.', 'warning');
    } else if (params.has('registered')) {
        showAlert(alertBox, 'Account registered successfully! You may now sign in.', 'success');
    } else if (params.has('pwd_changed')) {
        showAlert(alertBox, 'Password updated successfully. Please log in with your new password.', 'success');
    } else if (params.has('reset_success')) {
        showAlert(alertBox, 'Password reset successful. You may now log in with your new password.', 'success');
    }
}

/* --- Helper: Show Alert Message --- */
function showAlert(el, message, type = 'error') {
    if (!el) return;
    el.className = `alert-box alert-${type}`;
    el.textContent = message;
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideAlert(el) {
    if (!el) return;
    el.className = 'alert-box alert-hidden';
    el.textContent = '';
}

function setBtnLoading(btn, isLoading, defaultText) {
    const textSpan = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.spinner');
    if (isLoading) {
        btn.disabled = true;
        if (spinner) spinner.classList.remove('hidden');
        if (textSpan) textSpan.textContent = 'Processing...';
    } else {
        btn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (textSpan) textSpan.textContent = defaultText;
    }
}

/* --- Login Form Handling --- */
function initLoginForm() {
    const form = document.getElementById('login-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const alertBox = document.getElementById('login-alert');
        const submitBtn = document.getElementById('login-submit-btn');
        hideAlert(alertBox);

        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;

        if (!email || !password) {
            showAlert(alertBox, 'Institutional email and password are both required.');
            return;
        }

        setBtnLoading(submitBtn, true, 'Authenticate');

        try {
            const resp = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(alertBox, 'Authentication successful! Redirecting...', 'success');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 600);
            } else {
                showAlert(alertBox, data.detail || 'Authentication failed. Please verify your credentials.');
            }
        } catch (err) {
            showAlert(alertBox, 'Network communication error. Check server availability.');
        } finally {
            setBtnLoading(submitBtn, false, 'Authenticate');
        }
    });
}

/* --- Real-Time Password Policy Evaluator --- */
function evaluatePasswordPolicy(password, confirmPassword, email, studentId, prefix = '') {
    const p = password || '';
    const c = confirmPassword || '';

    const checks = {
        len: p.length >= 12,
        upper: /[A-Z]/.test(p),
        lower: /[a-z]/.test(p),
        num: /[0-9]/.test(p),
        spec: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(p),
        match: p.length > 0 && p === c,
        ident: true
    };

    if (email && email.length >= 3) {
        const emailLower = email.toLowerCase();
        const local = emailLower.split('@')[0];
        if (p.toLowerCase().includes(emailLower) || (local.length >= 3 && p.toLowerCase().includes(local))) {
            checks.ident = false;
        }
    }
    if (studentId && studentId.length >= 3) {
        if (p.toLowerCase().includes(studentId.toLowerCase())) {
            checks.ident = false;
        }
    }

    // Update DOM indicators
    updateReqEl(`${prefix}req-len`, checks.len);
    updateReqEl(`${prefix}req-upper`, checks.upper);
    updateReqEl(`${prefix}req-lower`, checks.lower);
    updateReqEl(`${prefix}req-num`, checks.num);
    updateReqEl(`${prefix}req-spec`, checks.spec);
    if (document.getElementById(`${prefix}req-ident`)) {
        updateReqEl(`${prefix}req-ident`, checks.ident);
    }
    updateReqEl(`${prefix}req-match`, checks.match);

    // Calculate score
    const passedCount = Object.values(checks).filter(Boolean).length;
    const strengthBar = document.getElementById(`${prefix}strength-bar-fill`);
    const strengthLabel = document.getElementById(`${prefix}strength-label`);

    if (strengthBar && strengthLabel) {
        if (p.length === 0) {
            strengthBar.className = 'strength-bar-fill strength-0';
            strengthLabel.className = 'badge badge-neutral';
            strengthLabel.textContent = 'Awaiting input';
        } else if (passedCount <= 3) {
            strengthBar.className = 'strength-bar-fill strength-1';
            strengthLabel.className = 'badge badge-danger';
            strengthLabel.textContent = 'Weak';
        } else if (passedCount <= 5) {
            strengthBar.className = 'strength-bar-fill strength-2';
            strengthLabel.className = 'badge badge-warning';
            strengthLabel.textContent = 'Moderate';
        } else if (passedCount === 6) {
            strengthBar.className = 'strength-bar-fill strength-3';
            strengthLabel.className = 'badge badge-warning';
            strengthLabel.textContent = 'Good';
        } else {
            strengthBar.className = 'strength-bar-fill strength-4';
            strengthLabel.className = 'badge badge-success';
            strengthLabel.textContent = 'Strong Policy Match';
        }
    }

    return Object.values(checks).every(Boolean);
}

function updateReqEl(id, isValid) {
    const el = document.getElementById(id);
    if (!el) return;
    if (isValid) {
        el.className = 'policy-item valid';
        el.querySelector('.icon').textContent = '✓';
    } else {
        el.className = 'policy-item invalid';
        el.querySelector('.icon').textContent = '•';
    }
}

/* --- Register Form Handling --- */
function initRegisterForm() {
    const form = document.getElementById('register-form');
    if (!form) return;

    const pwdInput = document.getElementById('reg-password');
    const confInput = document.getElementById('confirm_password');
    const emailInput = document.getElementById('reg-email');
    const sidInput = document.getElementById('student_id');

    const updatePolicy = () => {
        evaluatePasswordPolicy(
            pwdInput.value,
            confInput.value,
            emailInput.value,
            sidInput.value,
            ''
        );
    };

    pwdInput.addEventListener('input', updatePolicy);
    confInput.addEventListener('input', updatePolicy);
    emailInput.addEventListener('input', updatePolicy);
    sidInput.addEventListener('input', updatePolicy);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const alertBox = document.getElementById('register-alert');
        const submitBtn = document.getElementById('register-submit-btn');
        hideAlert(alertBox);

        const fullName = document.getElementById('full_name').value.trim();
        const studentId = sidInput.value.trim();
        const email = emailInput.value.trim();
        const password = pwdInput.value;
        const confirmPassword = confInput.value;

        if (!fullName || !studentId || !email || !password || !confirmPassword) {
            showAlert(alertBox, 'All registration fields are required.');
            return;
        }

        const isValid = evaluatePasswordPolicy(password, confirmPassword, email, studentId, '');
        if (!isValid) {
            showAlert(alertBox, 'Password does not meet the mandatory security policy requirements.');
            return;
        }

        setBtnLoading(submitBtn, true, 'Create Secure Account');

        try {
            const resp = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    full_name: fullName,
                    student_id: studentId,
                    email: email,
                    password: password,
                    confirm_password: confirmPassword
                })
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(alertBox, 'Registration complete! Redirecting to sign in...', 'success');
                setTimeout(() => {
                    window.location.href = '/login?registered=1';
                }, 800);
            } else {
                showAlert(alertBox, data.detail || 'Registration failed.');
            }
        } catch (err) {
            showAlert(alertBox, 'Communication failure during registration.');
        } finally {
            setBtnLoading(submitBtn, false, 'Create Secure Account');
        }
    });
}

/* --- Change Password Form Handling --- */
function initChangePasswordForm() {
    const form = document.getElementById('change-pwd-form');
    if (!form) return;

    const newPwdInput = document.getElementById('chg-new-password');
    const confInput = document.getElementById('chg-confirm-password');

    const updatePolicy = () => {
        evaluatePasswordPolicy(newPwdInput.value, confInput.value, '', '', 'chg-');
    };

    newPwdInput.addEventListener('input', updatePolicy);
    confInput.addEventListener('input', updatePolicy);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const alertBox = document.getElementById('change-pwd-alert');
        const submitBtn = document.getElementById('change-pwd-submit-btn');
        hideAlert(alertBox);

        const currentPassword = document.getElementById('current_password').value;
        const newPassword = newPwdInput.value;
        const confirmNewPassword = confInput.value;

        if (!currentPassword || !newPassword || !confirmNewPassword) {
            showAlert(alertBox, 'All fields are required.');
            return;
        }

        if (currentPassword === newPassword) {
            showAlert(alertBox, 'New password must be different from current password.');
            return;
        }

        setBtnLoading(submitBtn, true, 'Apply New Password');

        try {
            const resp = await fetch('/api/auth/change-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_new_password: confirmNewPassword
                })
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(alertBox, 'Password updated successfully! Redirecting to sign in...', 'success');
                setTimeout(() => {
                    window.location.href = '/login?pwd_changed=1';
                }, 1000);
            } else {
                showAlert(alertBox, data.detail || 'Password change rejected.');
            }
        } catch (err) {
            showAlert(alertBox, 'Error contacting authentication server.');
        } finally {
            setBtnLoading(submitBtn, false, 'Apply New Password');
        }
    });
}

/* --- Recovery Flow Handling --- */
function initRecoveryFlow() {
    const reqForm = document.getElementById('recovery-req-form');
    const resetForm = document.getElementById('recovery-reset-form');
    if (!reqForm || !resetForm) return;

    const alertBox = document.getElementById('recovery-alert');
    const devBanner = document.getElementById('dev-token-banner');
    const devTokenVal = document.getElementById('dev-token-value');
    const copyBtn = document.getElementById('copy-token-btn');

    // Token Request Form
    reqForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(alertBox);
        const reqBtn = document.getElementById('request-token-btn');
        const identifier = document.getElementById('identifier').value.trim();

        if (!identifier) {
            showAlert(alertBox, 'Institutional email or student ID is required.');
            return;
        }

        setBtnLoading(reqBtn, true, 'Generate Recovery Token');

        try {
            const resp = await fetch('/api/auth/recovery/request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier })
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(alertBox, data.message, 'success');
                if (data.dev_token && devBanner && devTokenVal) {
                    devTokenVal.value = data.dev_token;
                    devBanner.classList.remove('hidden');
                }
            } else {
                showAlert(alertBox, data.detail || 'Recovery request could not be processed.');
            }
        } catch (err) {
            showAlert(alertBox, 'Network failure during recovery request.');
        } finally {
            setBtnLoading(reqBtn, false, 'Generate Recovery Token');
        }
    });

    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const tokenInput = document.getElementById('recovery-token');
            if (tokenInput && devTokenVal) {
                tokenInput.value = devTokenVal.value;
                showAlert(alertBox, 'Recovery token populated in Step 2.', 'success');
                tokenInput.scrollIntoView({ behavior: 'smooth' });
            }
        });
    }

    // Reset Password Form
    const recNewPwd = document.getElementById('rec-new-password');
    const recConfPwd = document.getElementById('rec-confirm-password');

    const updateRecPolicy = () => {
        evaluatePasswordPolicy(recNewPwd.value, recConfPwd.value, '', '', 'rec-');
    };

    recNewPwd.addEventListener('input', updateRecPolicy);
    recConfPwd.addEventListener('input', updateRecPolicy);

    resetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(alertBox);
        const resetBtn = document.getElementById('reset-pwd-submit-btn');

        const token = document.getElementById('recovery-token').value.trim();
        const newPassword = recNewPwd.value;
        const confirmNewPassword = recConfPwd.value;

        if (!token || !newPassword || !confirmNewPassword) {
            showAlert(alertBox, 'Recovery token and new passwords are required.');
            return;
        }

        setBtnLoading(resetBtn, true, 'Reset Password & Unlock Account');

        try {
            const resp = await fetch('/api/auth/recovery/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token,
                    new_password: newPassword,
                    confirm_new_password: confirmNewPassword
                })
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(alertBox, 'Password reset successful! Redirecting to login...', 'success');
                setTimeout(() => {
                    window.location.href = '/login?reset_success=1';
                }, 1000);
            } else {
                showAlert(alertBox, data.detail || 'Password reset rejected.');
            }
        } catch (err) {
            showAlert(alertBox, 'Network communication error during password reset.');
        } finally {
            setBtnLoading(resetBtn, false, 'Reset Password & Unlock Account');
        }
    });
}
