//-------- Model for an individual Flows Removed Bytes Source Sent Chart:
nmeta.FlowsRemovedBytesSrcSentChartModel = Backbone.Model.extend({
    urlRoot:'/v1/flows_removed/stats/src_bytes_sent',

    initialize : function(){
        // The number of top values to individually chart: 
        this.TOPN = 5
        // Initiate and pre-populate arrays to hold data in correct format
        // for ChartJS:
        this.flows_removed_bytes_src_sent_labels = [];
        this.flows_removed_bytes_src_sent_data = [];
    },

    parse:function (response) {
        // Parse response data from under _items key:
        api_data = response._items;
        console.log('api_data=' + JSON.stringify(api_data));
        // Populate data in format for ChartJS:
        var count;
        var other = 0;
        for(count = 0; count < api_data.length; count++){
            if (count < this.TOPN) {
                this.flows_removed_bytes_src_sent_labels.push(api_data[count].identity);
                this.flows_removed_bytes_src_sent_data.push(api_data[count].total_bytes_sent);
            } else {
                // Aggregate into 'other' category:
                if (this.flows_removed_bytes_src_sent_labels.length == this.TOPN) {
                    this.flows_removed_bytes_src_sent_labels[this.TOPN] = 'Other';
                }
                other = other + api_data[count].total_bytes_sent; 
                this.flows_removed_bytes_src_sent_data[this.TOPN] = other;
            }
        }
        console.log('this.flows_removed_bytes_src_sent_labels=' + this.flows_removed_bytes_src_sent_labels);
        console.log('this.flows_removed_bytes_src_sent_data=' + this.flows_removed_bytes_src_sent_data);
        
        // Return the modified root response:
        return api_data;
    },
});
