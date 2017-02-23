nmeta.PolicyView = Backbone.View.extend({

    events:{
        "click #showMeBtn":"showMeBtnClick"
    },

    render:function () {
        this.$el.html(this.template());
        return this;
    },

});
