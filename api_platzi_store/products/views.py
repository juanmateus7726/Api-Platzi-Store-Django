from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests

URL = "https://api.escuelajs.co/api/v1/products"

def store_view(request):
    return render(request, 'store.html')

def products_view(request):
    try:
        response = requests.get(URL)
        if response.status_code == 200:
            products = response.json()
            context = {"products": products, "api_status": "success"}
        else:
            context = {"products": [], "error": "Error en la API", "api_status": "error"}
    except Exception as e:
        context = {"products": [], "error": str(e), "api_status": "error"}
    return render(request, "products.html", context)

def product_detail_view(request, product_id):
    try:
        response = requests.get(f"{URL}/{product_id}")
        if response.status_code == 200:
            product = response.json()
            context = {"product": product, "api_status": "success"}
        else:
            context = {"product": None, "error": "Producto no encontrado", "api_status": "error"}
    except Exception as e:
        context = {"product": None, "error": str(e), "api_status": "error"}
    return render(request, "product_detail.html", context)

@csrf_exempt
def add_product_view(request):
    if request.method == "POST":
        data = {
            "title": request.POST.get("title"),
            "price": int(request.POST.get("price")),
            "description": request.POST.get("description"),
            "categoryId": int(request.POST.get("categoryId")),
            "images": [request.POST.get("image")]
        }
        response = requests.post(URL, json=data)
        if response.status_code in [200, 201]:
            return redirect("products:products")
        return render(request, "add_product.html", {"error": "No se pudo crear"})
    return render(request, "add_product.html")

@csrf_exempt
def update_product_view(request, product_id):
    if request.method == "POST":
        data = {
            "title": request.POST.get("title"),
            "price": int(request.POST.get("price")),
            "description": request.POST.get("description"),
            "categoryId": int(request.POST.get("categoryId")),
            "images": [request.POST.get("image")]
        }
        response = requests.put(f"{URL}/{product_id}", json=data)
        if response.status_code == 200:
            return redirect("products:product_detail", product_id=product_id)
        return render(request, "update_product.html", {"error": "No se pudo actualizar"})
    return render(request, "update_product.html", {"product_id": product_id})

@csrf_exempt
def delete_product_view(request, product_id):
    if request.method == "POST":
        response = requests.delete(f"{URL}/{product_id}")
        if response.status_code == 200:
            return redirect("products:products")
        return JsonResponse({"error": "No se pudo eliminar"}, status=500)
    return redirect("products:products")


