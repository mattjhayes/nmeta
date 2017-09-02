nmeta.IdentitiesPaginatorView = Backbone.View.extend({

    initialize:function (options) {
        // Initialise the paginator
        this.paginator = new Backgrid.Extension.Paginator({
            collection: this.model
        });
    },

    render:function () {
        console.log('IdentitiesPaginatorView render function');

        // Start with empty el:
        this.$el.empty();

        // Render the paginator:
        this.$el.append(this.paginator.render().el);

        return this;
    },

});
