from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

class UserRegistrationSerializer(serializers.ModelSerializer):
    """  
    Serializer para el registro de nuevos usuarios.
    Valida y crea un nuevo usuario en el sistema.
    """
    # Campo adicional para confirmar la contrasena
    password2 = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label='Confirmar contrasena'
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'first_name', 'last_name']
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'}
            },
            'email': {'required': True}
        }
    
    def Validate(self, attrs):
        """  
        Valida que las contrasenas coincidan y cumplan los requisitos minimos.
        """
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({
                'password': 'Las contrasenas no coinciden'
            })
        
        # Validacion de longitud minima de contrasena
        if len(attrs['password']) < 8:
            raise serializers.ValidationError({
                'password': 'La contrasena debe tener al menos 8 caracteres'
            })
        
        return attrs
    
    def validate_email(self, value):
        """ 
        Valida que el email no este ya registrado en el sistema.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'Ya existe un usuario con este correo electronico'
            )
        return value
    
    def create(self, validated_data):
        """ 
        Crea un nuevo usuario con los datos validos.
        """
        # Removemos password2 ya que no es parte del modelo User
        validated_data.pop('password2')
        # Creamos el usuario usando el metodo create_user para hashear la contrasena
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name', ''],
            last_name=validated_data['last_name', '']
        )
        
        return user
    
class UserLoginSerializer(serializers.Serializer):
    """ 
    Serializzer para el inicio de sesion de usuarios.
    Valida las credenciales y autentica al usuario.
    """
    username = serializers.CharField(
        max_length=255,
        help_text='Nombre de usuario para iniciar sesion'
    )
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        help_text='Contrasena del usuario'
    )
    
    def validate(self, attrs):
        """ 
        Valida las credenciales del usuario.
        """
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # Intentamos autenticar al usuario
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )
            
            if not user:
                # Si la autenticacion falla, lanzamos un error
                raise serializers.ValidationError(
                    'Esta cuenta esta desactivada',
                    code='inactive'
                )
                
            # Guardamos el usuario autenticado en los datos validados
            attrs['user'] = user
            return attrs
        else:
            # Si faltan campos requeridos
            raise serializers.ValidationError(
                'Debe incluir usuario y contrasena',
                code='required'
            )

class UserSerializer(serializers.ModelSerializer):
    """ 
    Serializer para mostrar informacion del usuario.
    se usa para devolver datos del usuario despues del login o registro.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'is_active']
        read_only_fields = ['id', 'date_joined', 'is_active']