//-------- Model for an individual identity:
nmeta.IdentityModel = Backbone.Model.extend({
    });

//-------- Collection of Identity models:
nmeta.IdentitiesCollection = Backbone.Collection.extend({
        model:nmeta.IdentityModel,
        url:'/v1/identities/ui?filter_dns=1',
        parse:function (response) {
            console.log(response._items);
            response.id = response._id;
            //--- Parse response data from under _items key:
            return response._items;
        }
    });

