//-------- Model for an individual identity:
nmeta.IdentityPageableModel = Backbone.Model.extend({
    });

//-------- Collection of Identity models:
nmeta.IdentitiesPageableCollection = Backbone.PageableCollection.extend({

    model:nmeta.IdentityPageableModel,

    url:'/v1/identities/ui?filter_dns=1',

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

