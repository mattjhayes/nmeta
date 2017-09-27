nmeta.FlowsRemovedBytesSentChartView = Backbone.View.extend({

    initialize:function () {
        this.model.on("sync", this.render, this);
    },

    // Render ChartJS Chart:
    render: function(){
        console.log('in flows removed render...');
        $(this.el).html(this.template());

        // ChartJS configuration parameters:
        var data = {
            labels: this.model.flows_removed_stats_bytes_sent_labels,
            datasets: [
                    {
                    label: "Flows Removed Bytes Sent",
                    // Use data from model:
                    data: this.model.flows_removed_stats_bytes_sent_data
                }
            ]
        };
        var options = {
            title:{
                display:true,
                text:"Flows Removed Bytes Sent"
            },
        };
        var ctx = $('#FlowsRemovedBytesSentChart', this.el)[0].getContext("2d");
        
        var FlowsRemovedBytesSentChart = new Chart(ctx, {
            type: 'pie',
            data: data,
            options: options
        });
    }
})

