from django.urls import path
from . import views

app_name = 'products'

urlpatterns = [
    path('', views.store_view, name='store'),
    path('products/', views.products_view, name='products'),
    path('products/<int:product_id>/', views.product_detail_view, name='product_detail'),
    path('products/add/', views.add_product_view, name='add_product'),
    path('products/<int:product_id>/update/', views.update_product_view, name='update_product'),
    path('products/<int:product_id>/delete/', views.delete_product_view, name='delete_product'),
]