nmeta.ControllerPIRateChartView = Backbone.View.extend({

    initialize:function () {
        // Listen for custom event from model that says it's render time:
        this.model.on('event_controller_pirate_data', this.render, this);

        // Start regular polling for new data in model:
        this.model.startPolling();
    },

    // Render ChartJS Chart:
    render: function(){
        $(this.el).html(this.template());

        // ChartJS configuration parameters:
        var data = {
            labels: this.model.pi_rate_x_labels,
            datasets: [
                    {
                    label: "Nmeta Time",
                    backgroundColor: "rgba(204,131,20,1)",
                    // Use data from model:
                    data: this.model.pi_rate_data
                }
            ]
        };
        var options = {
            // Boolean - Whether grid lines are shown across the chart
            scaleShowGridLines : true,
            title:{
                display:true,
                text:"Average Packet-In Event Rate"
            },
            scales: {
                    xAxes: [{
                        stacked: true,
                    }],
                    yAxes: [{
                        stacked: true,
                        scaleLabel: {
                            display: true,
                            labelString: 'Events per Second'
                        }
                    }]
                }
            };
        var ctx = $('#PIRateChart', this.el)[0].getContext("2d");
        
        var myLineChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: options
        });
    }
})

