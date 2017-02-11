//-------- Model for an individual flow:
nmeta.FlowModel = Backbone.Model.extend({
    });

//-------- Collection of Flow models:
nmeta.FlowsCollection = Backbone.Collection.extend({
        model:nmeta.FlowModel,
        url:'/v1/flows/ui',
        parse:function (response) {
            console.log(response._items);
            response.id = response._id;
            //--- Parse response data from under _items key:
            return response._items;
        }
    });

