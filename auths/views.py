import os, requests, jwt

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from auths.models import MutsaUser
from auths.serializers import KakaoLoginRequestSerilalizer, KakaoRegisterRequestSerializer, MutsaUserResponseSerializer

class KakaoAccessTokenException(Exception):
    pass

class KakaoOIDCException(Exception):
    pass

class KakaoDataException(Exception):
    pass

#카카오 액세스 토큰 교환 함수
def exchange_kakao_access_token(code): 
    response = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': code,
        },
    )

    if response.status_code >= 300:
        raise KakaoAccessTokenException()

    return response.json()

#JWT 토큰에서 카카오 닉네임을 추출    
def extract_kakao_nickname(kakao_data): 
    id_token = kakao_data.get('id_token', None)
    if id_token is None:
        raise KakaoDataException()
        
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    signing_algol = jwt.get_unverified_header(id_token)['alg']
    try:
        payload = jwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=[signing_algol],
            audience=os.environ.get('KAKAO_REST_API_KEY'),
        )
    except jwt.InvalidTokenError:
        raise KakaoOIDCException()
    return payload['nickname']
 
#카카오 로그인 - 클라이언트로부터 받은 access code 사용하여 로그인 처리 
# -> access token 교환 후 jwt를 디코드하여 닉네임 추출
# -> 닉네임으로 사용자 조회 후 토큰 발급   
@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_login(request): 
    serializer = KakaoLoginRequestSerilalizer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    
    try:
        kakao_data = exchange_kakao_access_token(data['code'])
        nickname = extract_kakao_nickname(kakao_data)
    except KakaoAccessTokenException:
        return Response({'detail' : 'Access token 교환에 실패했습니다.'}, status = 401)
        
    except KakaoDataException:
        return Response({'detail' : 'OIDC token 정보를 확인할 수 없습니다.'}, status = 401)
    
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status = 401)
        
    
    try: 
        user = MutsaUser.objects.get(nickname=nickname)
    except MutsaUser.DoesNotExist:
        return Response({'detail': '존재하지 않는 사용자입니다.'}, status=404)
        
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token' : str(refresh.access_token),
        'refresh_token': str(refresh)
    })
    
    
    
#카카오 회원가입 - 클라이언트로부터 받은 액세스 코드를 사용하여 회원가입 처리
# -> 액세스 토큰 교환 후 jwt 디코드하여 닉네임 추출
# -> 닉네임으로 사용자 조회 후, 중복 사용자 존재 여부 확인 후 신규 사용자 생성    
@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_register(request):
    serializer = KakaoRegisterRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception = True)
    data = serializer.validated_data
    
    try:
        kakao_data = exchange_kakao_access_token(data['code'])
        nickname = extract_kakao_nickname(kakao_data)
    except KakaoAccessTokenException:
        return Response({'detail': 'Access token 교환에 실패했습니다.'}, status=401)
        
    except KakaoDataException:
        return Response({'detail': 'OIDC token 정보를 확인할 수 없습니다.'}, status=401)
        
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status=401)

    notuser = False
    
    try:
        user = MutsaUser.objects.get(nickname=nickname)
    except MutsaUser.DoesNotExist:
        notuser = True

    if not notuser:
        return Response({'detail': '이미 등록 된 사용자를 중복 등록할 수 없습니다.'}, status=400)

    user = MutsaUser.objects.create_user(nickname=nickname, description=data['description'])
    refresh = RefreshToken.for_user(user)
    
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    })
    
    
    
# 토큰 검증성 확인    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify(request):
    return Response({'detail': 'Token is verified. '}, status = 200)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail(request):
    serializer = MutsaUserResponseSerializer(request.user)
    return Response(serializer.data)
