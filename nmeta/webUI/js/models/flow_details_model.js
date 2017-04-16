//-------- Model for an individual event:
nmeta.FlowDetailModel = Backbone.Model.extend({
    });

//-------- Collection of Flow models:
nmeta.FlowDetailsCollection = Backbone.Collection.extend({

    model:nmeta.FlowDetailModel,

    url:'/v1/flows',

    parse:function (response) {
        // Uncomment this for debug of response:
        //console.log(JSON.stringify(response._items));
        response.id = response._id;
        //--- Parse response data from under _items key:
        return response._items;
    },

});

