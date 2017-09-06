nmeta.ControllerPITimeChartView = Backbone.View.extend({

    initialize:function () {
        // Listen for custom event from model that says it's render time:
        this.model.on('event_controller_pitime_data', this.render, this);

        // Start regular polling for new data in model:
        this.model.startPolling();
    },

    // Render ChartJS Chart:
    render: function(){
        $(this.el).html(this.template());

        // ChartJS configuration parameters:
        var data = {
            labels: this.model.chart_x_labels,
            datasets: [
                    {
                    label: "Nmeta Time",
                    backgroundColor: "rgba(204,131,20,1)",
                    // Use data from model:
                    data: this.model.nmeta_time_data
                },
                    {
                    label: "Ryu Time (includes queueing)",
                    backgroundColor: "rgba(51,153,255,1)",
                    // Use data from model:
                    data: this.model.ryu_time_data
                }
            ]
        };
        var options = {
            // Boolean - Whether grid lines are shown across the chart
            scaleShowGridLines : true,
            // Turn off animated drawing of chart on every poll:
            animation : false,
            // Disable aspect ratio to allow setting of chart height:
            maintainAspectRatio: false,
            title:{
                display:true,
                text:"Average Controller Packet-In Processing Time - Stacked"
            },
            scales: {
                xAxes: [{
                    stacked: true,
                }],
                yAxes: [{
                    stacked: true,
                    scaleLabel: {
                        display: true,
                        labelString: 'Processing Time (Seconds)'
                    }
                }]
            },
            elements: {
                point: {
                    // Disable dots on chart:
                    radius: 0
                }
            }
        };
        var ctx = $('#PITimeChart', this.el)[0].getContext("2d");
        // Chart height:
        //ctx.height = 120;
        
        var PITimeChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: options
        });
    }
})

