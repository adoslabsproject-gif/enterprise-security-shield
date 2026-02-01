/**
 * Enterprise Security Shield - Dashboard JavaScript
 *
 * No inline scripts - CSP compliant (A+ security headers)
 * Uses data attributes for configuration
 */

(function() {
    'use strict';

    /**
     * ESS Dashboard Module
     */
    const EssDashboard = {
        /**
         * Initialize the dashboard
         */
        init: function() {
            this.initScoreBars();
            this.initCharts();
            this.initFormSubmits();
        },

        /**
         * Initialize score bars with CSS custom properties
         */
        initScoreBars: function() {
            const scoreBars = document.querySelectorAll('.ess-score-bar__fill[data-score]');

            scoreBars.forEach(function(bar) {
                const score = parseInt(bar.dataset.score, 10) || 0;
                // Use data attribute instead of inline style for CSP compliance
                bar.setAttribute('data-score-value', score);
            });
        },

        /**
         * Initialize Chart.js charts
         */
        initCharts: function() {
            const dashboard = document.querySelector('.ess-dashboard[data-chart-config]');

            if (!dashboard) {
                return;
            }

            let config;
            try {
                config = JSON.parse(dashboard.dataset.chartConfig);
            } catch (e) {
                console.error('ESS Dashboard: Invalid chart config', e);
                return;
            }

            this.initThreatChart(config);
            this.initAttackTypesChart(config);
        },

        /**
         * Initialize threat activity line chart
         * @param {Object} config - Chart configuration from data attribute
         */
        initThreatChart: function(config) {
            const canvas = document.getElementById('ess-threat-chart');

            if (!canvas || typeof Chart === 'undefined') {
                return;
            }

            const ctx = canvas.getContext('2d');

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: config.hourlyLabels || [],
                    datasets: [
                        {
                            label: 'Threats',
                            data: config.hourlyThreats || [],
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 4
                        },
                        {
                            label: 'Requests',
                            data: config.hourlyRequests || [],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: 'index'
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            align: 'end',
                            labels: {
                                boxWidth: 12,
                                padding: 15,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleFont: {
                                size: 12
                            },
                            bodyFont: {
                                size: 12
                            },
                            padding: 10,
                            cornerRadius: 4
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                font: {
                                    size: 11
                                },
                                color: '#64748b'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: '#e2e8f0'
                            },
                            ticks: {
                                font: {
                                    size: 11
                                },
                                color: '#64748b'
                            }
                        }
                    }
                }
            });
        },

        /**
         * Initialize attack types doughnut chart
         * @param {Object} config - Chart configuration from data attribute
         */
        initAttackTypesChart: function(config) {
            const canvas = document.getElementById('ess-attack-types-chart');

            if (!canvas || typeof Chart === 'undefined') {
                return;
            }

            const ctx = canvas.getContext('2d');
            const attackTypes = config.attackTypes || {};

            const labels = Object.keys(attackTypes);
            const data = Object.values(attackTypes);

            const colors = [
                '#ef4444', // red - SQL Injection
                '#f59e0b', // amber - XSS
                '#8b5cf6', // violet - Path Traversal
                '#3b82f6', // blue - Scanner
                '#10b981', // emerald - Bot Spoofing
                '#ec4899', // pink - CMS Probe
                '#06b6d4', // cyan - Config Hunting
                '#84cc16', // lime - Rate Limit
                '#64748b'  // slate - Other
            ];

            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors.slice(0, labels.length),
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                boxWidth: 12,
                                padding: 10,
                                font: {
                                    size: 11
                                },
                                generateLabels: function(chart) {
                                    const data = chart.data;
                                    if (data.labels.length && data.datasets.length) {
                                        const total = data.datasets[0].data.reduce(function(a, b) {
                                            return a + b;
                                        }, 0);

                                        return data.labels.map(function(label, i) {
                                            const value = data.datasets[0].data[i];
                                            const percent = total > 0 ? Math.round((value / total) * 100) : 0;

                                            return {
                                                text: label + ' (' + percent + '%)',
                                                fillStyle: data.datasets[0].backgroundColor[i],
                                                hidden: false,
                                                index: i
                                            };
                                        });
                                    }
                                    return [];
                                }
                            }
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleFont: {
                                size: 12
                            },
                            bodyFont: {
                                size: 12
                            },
                            padding: 10,
                            cornerRadius: 4,
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce(function(a, b) {
                                        return a + b;
                                    }, 0);
                                    const value = context.raw;
                                    const percent = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return context.label + ': ' + value + ' (' + percent + '%)';
                                }
                            }
                        }
                    }
                }
            });
        },

        /**
         * Initialize form submission handlers
         */
        initFormSubmits: function() {
            const submitButtons = document.querySelectorAll('[data-ess-submit]');

            submitButtons.forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();

                    const form = this.closest('form');
                    if (!form) {
                        return;
                    }

                    // Add confirmation for ban/unban actions
                    const action = form.action || '';
                    const ip = form.querySelector('input[name="ip"]');
                    const ipValue = ip ? ip.value : '';

                    let confirmMessage = 'Are you sure?';

                    if (action.indexOf('/ban') !== -1) {
                        confirmMessage = 'Ban IP ' + ipValue + '? This will block all traffic from this address.';
                    } else if (action.indexOf('/unban') !== -1) {
                        confirmMessage = 'Unban IP ' + ipValue + '? This will allow traffic from this address again.';
                    }

                    if (confirm(confirmMessage)) {
                        form.submit();
                    }
                });
            });
        }
    };

    /**
     * Initialize on DOM ready
     */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            EssDashboard.init();
        });
    } else {
        EssDashboard.init();
    }

    // Expose for external use if needed
    window.EssDashboard = EssDashboard;

})();
