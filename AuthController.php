<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use OpenApi\Attributes as OA;

use App\Models\User;
use App\Models\UserToken;


class AuthController extends Controller
{
    public function __construct()
    {

    }

    #[OA\Post(
        path: '/api/login',
        tags: ['Auth'],
        summary: 'Connexion',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'password'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', example: "test@gmail.com"),
                    new OA\Property(property: 'password', type: 'string', example: "test1236"),
                ]
            )
        ),
        responses: [
            new OA\Response(response: 200, description: 'Utilisateur authentifié',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'user', ref: '#/components/schemas/User'),
                        new OA\Property(property: 'expires_in', type: 'integer', description: 'Secondes avant expiration'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 403, description: 'Compte désactivé'),
            new OA\Response(response: 404, description: 'Identifiants incorrects'),
            new OA\Response(response: 422, description: 'Erreur de validation'),
        ]
    )]

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email:rfc,dns',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'User not found',
                'errors' => "User not found"
            ], 404);
        }

        if (!$user->is_active) {
            return response()->json([
                'status' => 'error',
                'message' => 'Compte désactivé'
            ], 403);
        }

        // Générer un JTI unique avant de créer le token
        $jti = Str::random(32);

        // Créer le token avec le JTI personnalisé
        $custom_claims = ['jti' => $jti];
        $token = Auth::guard('api')->claims($custom_claims)->attempt([
            'email' => $request->email,
            'password' => $request->password,
        ]);

        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Identifiants incorrects'
            ], 401);
        }

        // Limiter le nombre de sessions actives à 5 appareils max
        $this->limitActiveSessions($user->id, 5);

        // Sauvegarder le token en DB
        UserToken::create([
            'user_id' => $user->id,
            'jti' => $jti,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'last_used_at' => now(),
            'expires_at' => now()->addMinutes(config('jwt.ttl')),
        ]);


        $user->load(['roles']);

        Log::info('AuthController-->login, User connecté', [
            'user_id' => $user->id,
            'email' => $user->email,
            'ip' => $request->ip()
        ]);

        return response()->json([
            'message' => 'User connecté',
            'token' => $token,
            'user' => $user,
            'token_type' => 'bearer',
            'expires_in' => Auth::guard('api')->factory()->getTTL() * 1440, // en secondes
        ], 200);
    }



    private function limitActiveSessions(int $userId, int $maxSessions = 5): void
    {
        $activeTokens = UserToken::where('user_id', $userId)
            ->where('expires_at', '>', now())
            ->orderBy('last_used_at', 'desc')
            ->get();

        // Si on dépasse la limite, supprimer les plus anciens
        if ($activeTokens->count() >= $maxSessions) {
            $tokensToDelete = $activeTokens->skip($maxSessions - 1);

            foreach ($tokensToDelete as $token) {
                $token->delete();
            }

            Log::info('Anciennes sessions supprimées', [
                'user_id' => $userId,
                'deleted_count' => $tokensToDelete->count()
            ]);
        }
    }


    #[OA\Post(
        path: '/api/refresh',
        tags: ['User'],
        summary: "Rafraîchir le token de l'utilisateur",
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(response: 200, description: 'Token rafraîchi',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'status', type: 'string'),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'token_type', type: 'string'),
                        new OA\Property(property: 'expires_in', type: 'integer'),
                        new OA\Property(property: 'user', ref: '#/components/schemas/User'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Token invalide ou refresh impossible'),
        ]
    )]

    public function refresh(Request $request)
    {
        try {
            // Récupérer l'ancien payload (peut être expiré, c'est OK)
            $old_payload = JWTAuth::parseToken()->getPayload();
            $old_jti = $old_payload->get('jti');
            $user_id = $old_payload->get('sub');


            $old_token_record = UserToken::where('jti', $old_jti)
                ->where('user_id', $user_id)
                ->first();

            if (!$old_token_record) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token révoqué ou invalide'
                ], 401);
            }

            // 3. Vérifier que le token n'est pas expiré depuis trop longtemps

            $refresh_ttl_minutes = config('jwt.refresh_ttl'); // 20160 min = 14 jours
            $max_refresh_date = $old_token_record->created_at->addMinutes($refresh_ttl_minutes);

            if (now()->greaterThan($max_refresh_date)) {
                // Token trop vieux pour être refreshé
                $old_token_record->delete();

                return response()->json([
                    'status' => 'error',
                    'message' => 'Token expiré depuis trop longtemps. Veuillez vous reconnecter.',
                    'code' => 'TOKEN_TOO_OLD'
                ], 401);
            }

            // Générer un nouveau JTI
            $new_jti = Str::random(32);

            $custom_claims = ['jti' => $new_jti];
            $new_token = Auth::guard('api')->claims($custom_claims)->refresh();


            $user = Auth::guard('api')->user();


            $old_token_record->delete();


            UserToken::create([
                'user_id' => $user->id,
                'jti' => $new_jti,
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'last_used_at' => now(),
                'expires_at' => now()->addMinutes(config('jwt.ttl')),
            ]);

            Log::info('AuthController-->refresh, token refreshed', [
                'user_id' => $user->id,
                'new_jti' => $new_jti
            ]);

            return response()->json([
                'message' => 'Token refreshed successfully',
                'token' => $new_token,
                'user' => $user,
                'token_type' => 'bearer',
                'expires_in' => Auth::guard('api')->factory()->getTTL() * 1440,
            ], 200);

        } catch (TokenExpiredException $e) {
            // Token expiré → C'est normal pour un refresh, mais on essaie quand même
            try {
                $new_jti = Str::random(32);
                $custom_claims = ['jti' => $new_jti];
                $new_token = Auth::guard('api')->claims($custom_claims)->refresh();

                $user = Auth::guard('api')->user();

                // Récupérer l'ancien JTI depuis le token expiré
                $old_payload = JWTAuth::setToken($request->bearerToken())->getPayload();
                $old_jti = $old_payload->get('jti');


                UserToken::where('jti', $old_jti)->delete();

                UserToken::create([
                    'user_id' => $user->id,
                    'jti' => $new_jti,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'last_used_at' => now(),
                    'expires_at' => now()->addMinutes(config('jwt.ttl')),
                ]);

                return response()->json([
                    'message' => 'Token expired but refreshed successfully',
                    'token' => $new_token,
                    'user' => $user,
                    'token_type' => 'bearer',
                    'expires_in' => Auth::guard('api')->factory()->getTTL() * 1440,
                ], 200);

            } catch (\Exception $inner_e) {
                Log::error('Refresh expired token failed', [
                    'message' => $inner_e->getMessage()
                ]);

                return response()->json([
                    'status' => 'error',
                    'message' => 'Token expiré et non rechargeable. Reconnectez-vous.',
                    'code' => 'REFRESH_FAILED'
                ], 401);
            }

        } catch (\Exception $e) {
            Log::error('Refresh token error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'status' => 'error',
                'message' => 'Token refresh failed',
                'errors' => $e->getMessage()
            ], 500);
        }
    }

}
