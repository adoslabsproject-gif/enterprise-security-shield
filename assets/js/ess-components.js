/**
 * Enterprise Security Shield - Component JavaScript
 *
 * No inline scripts - CSP compliant (A+ security headers)
 * Uses data attributes for configuration
 */

(function() {
    'use strict';

    /**
     * ESS Components Module
     */
    const EssComponents = {
        /**
         * Initialize all components
         */
        init: function() {
            this.initModals();
            this.initTabs();
            this.initRangeSliders();
            this.initScoreBars();
        },

        /**
         * Initialize modal functionality
         */
        initModals: function() {
            // Open modal buttons
            document.addEventListener('click', function(e) {
                const trigger = e.target.closest('[data-ess-modal]');
                if (trigger) {
                    e.preventDefault();
                    const modalId = 'ess-modal-' + trigger.dataset.essModal;
                    const modal = document.getElementById(modalId);
                    if (modal) {
                        EssComponents.openModal(modal);
                    }
                }
            });

            // Close modal buttons and backdrop
            document.addEventListener('click', function(e) {
                if (e.target.closest('[data-ess-modal-close]')) {
                    e.preventDefault();
                    const modal = e.target.closest('.ess-modal');
                    if (modal) {
                        EssComponents.closeModal(modal);
                    }
                }
            });

            // Close on escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    const openModal = document.querySelector('.ess-modal--open');
                    if (openModal) {
                        EssComponents.closeModal(openModal);
                    }
                }
            });
        },

        /**
         * Open a modal
         * @param {HTMLElement} modal - The modal element
         */
        openModal: function(modal) {
            modal.classList.add('ess-modal--open');
            document.body.style.overflow = 'hidden';

            // Focus first focusable element
            const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (focusable) {
                focusable.focus();
            }
        },

        /**
         * Close a modal
         * @param {HTMLElement} modal - The modal element
         */
        closeModal: function(modal) {
            modal.classList.remove('ess-modal--open');
            document.body.style.overflow = '';
        },

        /**
         * Initialize tabs functionality
         */
        initTabs: function() {
            const tabContainers = document.querySelectorAll('[data-ess-tabs]');

            tabContainers.forEach(function(container) {
                const buttons = container.querySelectorAll('[data-ess-tab]');
                const panels = container.querySelectorAll('[data-ess-panel]');

                buttons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        const tabId = this.dataset.essTab;

                        // Update button states
                        buttons.forEach(function(btn) {
                            btn.classList.remove('ess-tabs__btn--active');
                        });
                        this.classList.add('ess-tabs__btn--active');

                        // Update panel states
                        panels.forEach(function(panel) {
                            if (panel.dataset.essPanel === tabId) {
                                panel.classList.add('ess-tabs__panel--active');
                            } else {
                                panel.classList.remove('ess-tabs__panel--active');
                            }
                        });
                    });
                });
            });
        },

        /**
         * Initialize range slider value displays
         */
        initRangeSliders: function() {
            const rangeInputs = document.querySelectorAll('.ess-config-field__range');

            rangeInputs.forEach(function(input) {
                const container = input.closest('.ess-config-field');
                const valueDisplay = container ? container.querySelector('[data-ess-range-value]') : null;

                if (valueDisplay) {
                    // Initial value
                    EssComponents.updateRangeDisplay(input, valueDisplay);

                    // Update on change
                    input.addEventListener('input', function() {
                        EssComponents.updateRangeDisplay(this, valueDisplay);
                    });
                }
            });
        },

        /**
         * Update range slider display value
         * @param {HTMLElement} input - The range input
         * @param {HTMLElement} display - The display element
         */
        updateRangeDisplay: function(input, display) {
            let value = input.value;

            // Add % suffix for confidence threshold
            if (input.id === 'ess-confidence-threshold') {
                value = value + '%';
            }

            display.textContent = value;
        },

        /**
         * Initialize score bars with CSS custom properties
         */
        initScoreBars: function() {
            const scoreBars = document.querySelectorAll('.ess-score-bar__fill[data-score]');

            scoreBars.forEach(function(bar) {
                const score = parseInt(bar.dataset.score, 10) || 0;
                bar.style.setProperty('--ess-score', score);
            });
        }
    };

    /**
     * ESS Form Utilities
     */
    const EssFormUtils = {
        /**
         * Initialize form utilities
         */
        init: function() {
            this.initConfirmSubmits();
            this.initAsyncForms();
        },

        /**
         * Initialize forms that need confirmation
         */
        initConfirmSubmits: function() {
            const confirmForms = document.querySelectorAll('[data-ess-confirm]');

            confirmForms.forEach(function(form) {
                form.addEventListener('submit', function(e) {
                    const message = this.dataset.essConfirm || 'Are you sure?';
                    if (!confirm(message)) {
                        e.preventDefault();
                    }
                });
            });
        },

        /**
         * Initialize async form submission
         */
        initAsyncForms: function() {
            const asyncForms = document.querySelectorAll('[data-ess-async]');

            asyncForms.forEach(function(form) {
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    EssFormUtils.submitAsync(this);
                });
            });
        },

        /**
         * Submit form asynchronously
         * @param {HTMLFormElement} form - The form to submit
         */
        submitAsync: function(form) {
            const formData = new FormData(form);
            const submitBtn = form.querySelector('[type="submit"]');
            const originalText = submitBtn ? submitBtn.textContent : '';

            // Show loading state
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Loading...';
            }

            fetch(form.action, {
                method: form.method || 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(function(response) {
                return response.json();
            })
            .then(function(data) {
                if (data.success) {
                    // Show success message or reload
                    if (data.redirect) {
                        window.location.href = data.redirect;
                    } else if (data.reload) {
                        window.location.reload();
                    } else if (data.message) {
                        EssFormUtils.showNotification(data.message, 'success');
                    }
                } else {
                    EssFormUtils.showNotification(data.error || 'An error occurred', 'error');
                }
            })
            .catch(function(error) {
                console.error('Form submission error:', error);
                EssFormUtils.showNotification('An error occurred. Please try again.', 'error');
            })
            .finally(function() {
                // Reset button state
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }
            });
        },

        /**
         * Show notification message
         * @param {string} message - The message to show
         * @param {string} type - The notification type (success, error, warning)
         */
        showNotification: function(message, type) {
            // Remove existing notifications
            const existing = document.querySelector('.ess-notification');
            if (existing) {
                existing.remove();
            }

            // Create notification element
            const notification = document.createElement('div');
            notification.className = 'ess-notification ess-notification--' + type;
            notification.textContent = message;

            // Add to DOM
            document.body.appendChild(notification);

            // Trigger animation
            requestAnimationFrame(function() {
                notification.classList.add('ess-notification--visible');
            });

            // Auto-remove after 5 seconds
            setTimeout(function() {
                notification.classList.remove('ess-notification--visible');
                setTimeout(function() {
                    notification.remove();
                }, 300);
            }, 5000);
        }
    };

    /**
     * ESS Date Utilities
     */
    const EssDateUtils = {
        /**
         * Initialize date utilities
         */
        init: function() {
            this.formatRelativeDates();
        },

        /**
         * Format dates as relative time
         */
        formatRelativeDates: function() {
            const dateElements = document.querySelectorAll('.ess-datetime[data-timestamp]');

            dateElements.forEach(function(element) {
                const timestamp = element.dataset.timestamp;
                if (timestamp) {
                    const date = new Date(timestamp);
                    const relative = EssDateUtils.getRelativeTime(date);
                    element.setAttribute('title', date.toLocaleString());
                    if (relative) {
                        element.textContent = relative;
                    }
                }
            });
        },

        /**
         * Get relative time string
         * @param {Date} date - The date to format
         * @returns {string} Relative time string
         */
        getRelativeTime: function(date) {
            const now = new Date();
            const diff = now - date;
            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);

            if (seconds < 60) {
                return 'Just now';
            } else if (minutes < 60) {
                return minutes + ' min ago';
            } else if (hours < 24) {
                return hours + ' hour' + (hours === 1 ? '' : 's') + ' ago';
            } else if (days < 7) {
                return days + ' day' + (days === 1 ? '' : 's') + ' ago';
            } else {
                return null; // Use original date format
            }
        }
    };

    /**
     * Initialize on DOM ready
     */
    function init() {
        EssComponents.init();
        EssFormUtils.init();
        EssDateUtils.init();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose for external use
    window.EssComponents = EssComponents;
    window.EssFormUtils = EssFormUtils;
    window.EssDateUtils = EssDateUtils;

})();
