//-------- Model for an individual switch:
nmeta.SwitchModel = Backbone.Model.extend({
    });

//-------- Collection of switch models:
nmeta.SwitchesCollection = Backbone.Collection.extend({
        model:nmeta.SwitchModel,
        url:'/v1/infrastructure/switches',
        parse:function (response) {
            console.log(response._items);
            response.id = response._id;
            //--- Parse response data from under _items key:
            return response._items;
        }
    });

