//-------- Model for an individual Flows Removed Bytes Sent Chart:
nmeta.FlowsRemovedBytesSentChartModel = Backbone.Model.extend({
    urlRoot:'/v1/flows_removed/stats/bytes_sent',

    initialize : function(){
        // Initiate and pre-populate arrays to hold data in correct format
        // for ChartJS:
        this.flows_removed_stats_bytes_sent_labels = [];
        this.flows_removed_stats_bytes_sent_data = [];
    },

    parse:function (response) {
        // Parse response data from under _items key:
        api_data = response._items;
        console.log('api_data=' + JSON.stringify(api_data));
        // Populate data in format for ChartJS:
        var count;
        for(count = 0; count < api_data.length; count++){
            this.flows_removed_stats_bytes_sent_labels.push(api_data[count].identity);
            this.flows_removed_stats_bytes_sent_data.push(api_data[count].total_bytes_sent);
        }
        // Return the modified root response:
        return api_data;
    },
});

// An Item:
//                "_id": "10.1.0.2",
//                "identity": "10.1.0.2",
//                "total_bytes_sent": 3532
