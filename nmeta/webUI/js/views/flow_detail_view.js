nmeta.FlowDetailView = Backbone.View.extend({

    // Render flow detail view inside table tr tags:
    tagName:"tr",

    render:function () {
        // Render by attaching model to template to HTML:
        this.$el.html(this.template(this.model.attributes));
        return this;
    }

});
