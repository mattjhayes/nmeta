nmeta.SwitchView = Backbone.View.extend({

    // Render switch view inside table tr tags:
    tagName:"tr",

    initialize:function () {
        this.model.on("change", this.render, this);
        this.model.on("destroy", this.close, this);
    },

    render:function () {
        // Render by attaching model to template to HTML:
        this.$el.html(this.template(this.model.attributes));
        return this;
    }

});
