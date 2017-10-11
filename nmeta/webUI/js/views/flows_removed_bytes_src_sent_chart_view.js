nmeta.FlowsRemovedBytesSrcSentChartView = Backbone.View.extend({

    initialize:function () {
        this.model.on("sync", this.render, this);
        this.default_colors = ['#3366CC','#DC3912','#FF9900','#109618','#990099','#3B3EAC','#0099C6','#DD4477','#66AA00','#B82E2E','#316395','#994499','#22AA99','#AAAA11','#6633CC','#E67300','#8B0707','#329262','#5574A6','#3B3EAC']
    },

    // Render ChartJS Chart:
    render: function(){
        console.log('in flows removed render...');
        $(this.el).html(this.template());

        // ChartJS configuration parameters:
        var data = {
            labels: this.model.flows_removed_bytes_src_sent_labels,
            datasets: [
                    {
                    label: "Flows Removed Bytes Sent by Source",
                    // Use data from model:
                    data: this.model.flows_removed_bytes_src_sent_data,
                    // Fill colours to use in chart:
                    backgroundColor: this.default_colors
                }
            ]
        };
        var options = {
            title:{
                display:true,
                text:"Top Flows Removed by Source Bytes Sent"
            },
        };
        var ctx = $('#FlowsRemovedBytesSrcSentChart', this.el)[0].getContext("2d");
        
        var FlowsRemovedBytesSrcSentChart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: options
        });
    }
})

