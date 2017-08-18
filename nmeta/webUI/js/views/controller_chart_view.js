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
        this.labels = [];
        this.data = [];

        // Whitelist what API response attributes we want to include in chart:
        this.whitelist = ["pi_rate",
                          "pi_time_avg",
                          "pi_time_max",
                          "pi_time_min",
                          "ryu_time_avg",
                          "ryu_time_max",
                          "ryu_time_min"];

        // Iterate model response data and put into ChartJS format:
        _.each(this.model.attributes, function(val, key) {
                if( $.inArray(key, this.whitelist) != -1){
                    console.log('render key=' + key);
                    this.labels.push(key);
                    console.log('render value=' + val);
                    this.data.push(val);
                }
            }, this);

        // ChartJS configuration parameters:
        var data = {
            // Use labels from model:
            labels: this.labels,
            datasets: [
                {
                    label: "Controller Performance",
                    //backgroundColor: "rgba(255,153,0,1)",
                    backgroundColor: ["rgba(204,131,20,1)",
                                      "rgba(153,130,96,1)",
                                      "rgba(255,82,0,1)",
                                      "rgba(64,255,183,1)",
                                      "rgba(20,204,83,1)"],
                    // Use data from model:
                    data: this.data
                }
            ]
        };
        var options = {
            // Boolean - Whether grid lines are shown across the chart
            scaleShowGridLines : true,
        };

        var ctx = $('#myChart', this.el)[0].getContext("2d");
        
        var myLineChart = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: options
        });
    }
})

