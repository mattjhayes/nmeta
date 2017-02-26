//-------- Model for an individual flow:
nmeta.FlowModel = Backbone.Model.extend({
    });

//-------- Collection of Flow models:
nmeta.FlowsCollection = Backbone.Collection.extend({

    model:nmeta.FlowModel,

    url:'/v1/flows/ui',

    parse:function (response) {
        // Uncomment this for debug of response:
        //console.log(JSON.stringify(response._items));
        response.id = response._id;
        //--- Parse response data from under _items key:
        return response._items;
    },

    //--- Search flow src by name:
    search : function(searchTerm){
        if(searchTerm == "") return this;
        var pattern = new RegExp(searchTerm, "gi");
        return _(this.filter(function(data) {
            return pattern.test(data.get("src"));
            //return pattern.test(data);
        }));
    },

    //--- Search all attributes of flows:
    searchAll : function(searchTerm){
        if(searchTerm == "") return this;
        var pattern = new RegExp(searchTerm, "gi");
        return _.some(_.values(data.toJSON())), function(data) {
            if(data && data.toString) {
                return data.toString().toLowerCase().indexOf(searchTerm) >= 0;
            }
            return false;
        }
    }

});

