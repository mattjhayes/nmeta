nmeta.ControllerChartView = Backbone.View.extend({

    initialize:function () {
        var self = this;
        this.model.on("reset", this.render, this);
        this.model.on('change', this.render, this);
        

    },

    // Render ChartJS Chart:
    render: function(){
        console.log('In ControllerChartView render...');
        $(this.el).html(this.template());

        // Arrays to hold data in correct format for ChartJS:
        this.labels = ["Minimum", "Average", "Maximum"];
        this.ryu_time_data = [];
        this.nmeta_time_data = [];

        // Get model response data and put into ChartJS format:
        this.ryu_time_data.push(this.model.get("ryu_time_min"));
        this.ryu_time_data.push(this.model.get("ryu_time_avg"));
        this.ryu_time_data.push(this.model.get("ryu_time_max"));
        this.nmeta_time_data.push(this.model.get("pi_time_min"));
        this.nmeta_time_data.push(this.model.get("pi_time_avg"));
        this.nmeta_time_data.push(this.model.get("pi_time_max"));

        // ChartJS configuration parameters:
        var data = {
            // Use labels from model:
            labels: this.labels,
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
            type: 'bar',
            data: data,
            options: options
        });
    }
})

