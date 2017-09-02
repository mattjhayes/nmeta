//-------- Model for an individual flow:
nmeta.FlowPageableModel = Backbone.Model.extend({
    });

//-------- Collection of Flow models:
nmeta.FlowsPageableCollection = Backbone.PageableCollection.extend({

    model:nmeta.FlowPageableModel,

    url:'/v1/flows/ui',

    state: {
        pageSize: 15
    },

    mode: "client",

    parse:function (response) {
        // Uncomment this for debug of response:
        //console.log(JSON.stringify(response._items));
        response.id = response._id;
        //--- Parse response data from under _items key:
        return response._items;
    },

});

