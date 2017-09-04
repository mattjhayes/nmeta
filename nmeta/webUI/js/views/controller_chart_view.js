nmeta.ControllerChartView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        this.model.on('change', this.render, this);

        // Arrays to hold data in correct format for ChartJS:
        this.chart_x_labels = [];
        this.ryu_time_data = [];
        this.nmeta_time_data = [];
        
        // Start regular polling for new data in model:
        this.model.startPolling();

    },

    // Render ChartJS Chart:
    render: function(){
        console.log('In ControllerChartView render...');
        $(this.el).html(this.template());

        // Add timestamp to labels array:
        this.chart_x_labels.push(this.model.get("timestamp"));

        // Add values to data arrays:
        this.ryu_time_data.push(this.model.get("ryu_time_avg"));
        this.nmeta_time_data.push(this.model.get("pi_time_avg"));

        // TBD: stop arrays growing too long...
        

        // ChartJS configuration parameters:
        var data = {
            labels: this.chart_x_labels,
            datasets: [
                    {
                    label: "Nmeta Time",
                    backgroundColor: "rgba(204,131,20,1)",
                    // Use data from model:
                    data: this.nmeta_time_data
                },
                    {
                    label: "Ryu Time (includes queueing)",
                    backgroundColor: "rgba(51,153,255,1)",
                    // Use data from model:
                    data: this.ryu_time_data
                }
            ]
        };
        var options = {
            // Boolean - Whether grid lines are shown across the chart
            scaleShowGridLines : true,
            title:{
                display:true,
                text:"Packet Processing Time - Stacked"
            },
            scales: {
                    xAxes: [{
                        stacked: true,
                    }],
                    yAxes: [{
                        stacked: true,
                        scaleLabel: {
                            display: true,
                            labelString: 'Seconds'
                        }
                    }]
                }
            };
        var ctx = $('#myChart', this.el)[0].getContext("2d");
        
        var myLineChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: options
        });
    }
})

