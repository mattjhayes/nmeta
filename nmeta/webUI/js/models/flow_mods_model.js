//-------- Model for an individual event:
nmeta.FlowModModel = Backbone.Model.extend({
    });

//-------- Collection of Flow models:
nmeta.FlowModsCollection = Backbone.Collection.extend({

    model:nmeta.FlowModModel,

    url:'/v1/flow_mods',

    parse:function (response) {
        // Uncomment this for debug of response:
        //console.log(JSON.stringify(response._items));
        response.id = response._id;
        //--- Parse response data from under _items key:
        return response._items;
    },

    // Runs after API has returned successfully:
    //onFetch : function () {
        // Convert match JSONs to string:
        // var count;
        // for(count = 0; count < response.length; count++){
        // TBD, iterate response, using JSON.stringify()
    //}

});

