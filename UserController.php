<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;

use OpenApi\Attributes as OA;

use App\Models\User;
use App\Models\UserToken;


class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth:api', 'jwt.security']);
    }

    #[OA\Get(
        path: '/api/users',
        tags: ['User'],
        summary: 'Liste des utilisateurs',
        security: [['bearerAuth' => []]],
        parameters: [
            new OA\Parameter(
                name: 'page',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', example: 1)
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Liste des utilisateurs',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'data', type: 'array', items: new OA\Items(
                            ref: '#/components/schemas/User'
                        ))
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié')
        ]
    )]

    public function index(){
        $users = User::with(['roles'])->paginate(10);
        return response()->json($users, 200);
    }



   
    public function get_profile()
    {
        $user = Auth::guard('api')->user();

        $user->load(['roles', 'garanties', 'main_levees', 'documents']);
        $user->refresh();

        return response()->json([
            'status' => 'success',
            'user' => $user
        ], 200);
    }



    #[OA\Post(
        path: '/api/register',
        tags: ['User'],
        summary: 'Enregistrer un utilisateur',
        security: [['bearerAuth' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: [
                    'type',
                    'name',
                    'email',
                    'password',
                    'roles'
                ],
                properties: [
                    new OA\Property(property: 'type', type: 'string'),
                    new OA\Property(property: 'name', type: 'string'),
                    new OA\Property(property: 'email', type: 'string'),
                    new OA\Property(property: 'password', type: 'string'),
                    new OA\Property(property: 'phone', type: 'string', nullable: true),
                    new OA\Property(property: 'address', type: 'string', nullable: true),
                    new OA\Property(property: 'roles', type: 'string', example: "admin,user,auditeur"),
                ]
            )
        ),
        responses: [
            new OA\Response(response: 201, description: 'Utilisateur créée',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'user', ref: '#/components/schemas/User'),
                        new OA\Property(property: 'token_type', type: 'string'),
                        new OA\Property(property: 'expires_in', type: 'integer'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 409, description: 'Email déjà utilisé'),
            new OA\Response(response: 422, description: 'Erreur de validation'),
        ]
    )]

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'type' => 'required|string|max:255',
            'name' => 'required|string|max:255',
            'email' => 'required|email:rfc,dns',
            'password' => 'required|string|min:8',
            'phone' => 'nullable|string|max:255',
            'address' => 'nullable|string|max:255',
            'roles' => 'required|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $is_email_exist = User::where('email', $request->email)->first();
        if ($is_email_exist) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email already used',
                'errors' => "Email already used"
            ], 409);
        }

        try {
            $data = $request->all();
            $data['password'] = Hash::make(trim($data['password']));
            $data['uuid'] = Str::uuid()->toString();
            $data['name'] = Str::ucfirst(trim($data['name']));
            $data['is_active'] = true;
            $data['roles'] = [$request->roles];

            $user = User::create($data);
            $user->syncRoles($data['roles']);

            // Générer un JTI unique AVANT de créer le token
            $jti = Str::random(32);

            // Créer le token avec le JTI personnalisé
            $custom_claims = ['jti' => $jti];
            $token = Auth::guard('api')->claims($custom_claims)->login($user);


            UserToken::create([
                'user_id' => $user->id,
                'jti' => $jti,
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'last_used_at' => now(),
                'expires_at' => now()->addMinutes(config('jwt.ttl')),
            ]);

            $user->refresh();

            Log::info('UserController-->register new User', ['email' => $user->email]);

            return response()->json([
                'message' => 'Utilisateur enregistré',
                'token' => $token,
                'user' => $user,
                'token_type' => 'bearer',
                'expires_in' => Auth::guard('api')->factory()->getTTL() * 1440,
            ], 201);

        } catch (\Exception $e) {
            Log::error('API UserController-->register {message}', ['message' => $e->getMessage()]);
            return response()->json([
                'status' => 'error',
                'message' => "Echec lors de l'enregistrement",
                'error' => $e->getMessage()
            ], 500);
        }
    }



    #[OA\Put(
        path: '/api/users/update/{uuid}',
        tags: ['User'],
        summary: "Mettre à jour toutes les informations d'un utilisateur",
        security: [['bearerAuth' => []]],
        parameters: [
            new OA\Parameter(
                name: 'uuid',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string')
            )
        ],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: [
                    'type',
                    'name',
                    'email',
                    'password',
                    'roles',
                    'is_active'
                ],
                properties: [
                    new OA\Property(property: 'type', type: 'string'),
                    new OA\Property(property: 'name', type: 'string'),
                    new OA\Property(property: 'email', type: 'string'),
                    new OA\Property(property: 'password', type: 'string'),
                    new OA\Property(property: 'phone', type: 'string', nullable: true),
                    new OA\Property(property: 'address', type: 'string', nullable: true),
                    new OA\Property(property: 'roles', type: 'string', example: "admin,user,auditeur"),
                    new OA\Property(property: 'is_active', type: 'boolean', example: true),
                ]
            )
        ),
        responses: [
            new OA\Response(response: 200, description: 'Utilisateur mis à jour',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'user', ref: '#/components/schemas/User'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 403, description: 'Compte désactivé'),
            new OA\Response(response: 404, description: 'User non trouvé'),
            new OA\Response(response: 422, description: 'Erreur de validation'),
        ]
    )]

    public function update_credentials(String $uuid, Request $request)
    {
        $validator = Validator::make($request->all(), [
            'type' => 'required|string|max:255',
            'name' => 'required|string|max:255',
            'email' => 'required|email:rfc,dns',
            'password' => 'required|string|min:8',

            'phone' => 'nullable|string|max:255',
            'address' => 'nullable|string|max:255',
            'roles' => 'required|string|max:255',

            'is_active' => 'required|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::where('uuid', $uuid)->first();

        if(!$user){
            return response()->json([
                'status' => 'error',
                'message' => 'Compte non trouvé',
                'errors' => "Compte non trouvé"
            ], 404);
        }

        $old_email = $user->email;

        if($request->email !== $old_email){
            $is_email_exist = User::where('email', $request->email)->first();
            if($is_email_exist){
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email déjà existant',
                    'errors' => "Email déjà existant"
                ], 409);
            }
        }

        $data = $request->all();
        $data['password'] = Hash::make(trim($data['password']));
        $data['name'] = Str::ucfirst(trim($data['name']));
        $data['roles'] = [$request->roles];


        $user->update($data);


        $token = Auth::guard('api')->attempt([
                'email' => $request->email,
                'password' => $request->password,
            ]);

        if (!$token)
        {
            return response()->json([
                'status' => 'error',
                'message' => 'Identifiants incorrects'
            ], 401);
        }

        Log::info('UserController-->update credentials User ', ['email' => $user->email]);

        $user = User::where('email', $request->email)->first();

        if (!$user->is_active) {
            return response()->json([
                'status' => 'error',
                'message' => 'Compte désactivé'
            ], 403);
        }

        $user->refresh();

        return response()->json([
            'status' => 'success',
            'message' => 'Logged in successfully',
            'user' => $user,
            'token' => $token
        ], 200);
    }



    #[OA\Put(
        path: '/api/users/update_password',
        tags: ['User'],
        summary: "Mettre à jour uniquement le mot de passe de l'utilisateur",
        security: [['bearerAuth' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: [
                    'password',
                ],
                properties: [
                    new OA\Property(property: 'password', type: 'string'),
                ]
            )
        ),
        responses: [
            new OA\Response(response: 200, description: 'Utilisateur mis à jour',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'user', ref: '#/components/schemas/User'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 403, description: 'Compte désactivé'),
            new OA\Response(response: 404, description: 'User non trouvé'),
            new OA\Response(response: 422, description: 'Erreur de validation'),
        ]
    )]

    public function update_password(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = Auth::guard('api')->user();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'Compte non trouvé',
                'errors' => "Compte non trouvé"
            ], 404);
        }

        // Mettre à jour le mot de passe
        $user->update([
            'password' => Hash::make(trim($request->password))
        ]);

        // Révoquer tous les anciens tokens sauf le token actuel
        $current_jti = Auth::guard('api')->payload()->get('jti');

        $deleted_tokens = UserToken::where('user_id', $user->id)
            ->where('jti', '!=', $current_jti)
            ->delete();

        Log::info('UserController-->update_password, Password updated - old sessions revoked', [
            'user_id' => $user->id,
            'revoked_sessions' => $deleted_tokens
        ]);

        $user->refresh();
        $user->load(['roles']);

        // Créer un nouveau token
        $new_jti = Str::random(32);
        $custom_claims = ['jti' => $new_jti];

        $token = Auth::guard('api')->claims($custom_claims)->attempt([
            'email' => $user->email,
            'password' => $request->password,
        ]);

        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Identifiants incorrects'
            ], 401);
        }

        // Supprimer l'ancien token actuel
        UserToken::where('jti', $current_jti)->delete();

        // Créer le nouveau token en DB
        UserToken::create([
            'user_id' => $user->id,
            'jti' => $new_jti,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'last_used_at' => now(),
            'expires_at' => now()->addMinutes(config('jwt.ttl')),
        ]);

        return response()->json([
            'message' => 'Mot de passe modifié. Autres sessions déconnectées.',
            'token' => $token,
            'user' => $user,
            'token_type' => 'bearer',
            'expires_in' => Auth::guard('api')->factory()->getTTL() * 1440,
        ], 200);
    }



    #[OA\Post(
        path: '/api/logout',
        tags: ['User'],
        summary: "Déconnexion de l'utilisateur",
        security: [['bearerAuth' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: [],
                properties: [
                ]
            )
        ),
        responses: [
            new OA\Response(response: 200, description: 'Utilisateur déconnecté',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 422, description: 'Erreur de validation'),
        ]
    )]

    public function logout(Request $request)
    {
        try {
            // Récupérer le JTI du token actuel
            $payload = Auth::guard('api')->payload();
            $jti = $payload->get('jti');


            $deleted = UserToken::where('jti', $jti)->delete();

            Auth::guard('api')->logout(true); // true = invalider le token

            Log::info('UserController->logout, User logged out', [
                'user_id' => $payload->get('sub'),
                'jti' => $jti,
                'deleted_from_db' => $deleted
            ]);

            return response()->json([
                'message' => 'Utilisateur déconnecté avec succès'
            ], 200);

        } catch (\Exception $e) {
            Log::error('Logout error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'status' => 'error',
                'message' => 'Logout failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }


    #[OA\Post(
        path: '/api/logout_all',
        tags: ['User'],
        summary: "Déconnexion de tous les appareils",
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(response: 200, description: 'Déconnecté de tous les appareils'),
            new OA\Response(response: 401, description: 'Non authentifié'),
        ]
    )]
    public function logout_all(Request $request)
    {
        try {
            $user = Auth::guard('api')->user();

            // Supprimer tous les tokens de l'utilisateur
            $deleted_count = UserToken::where('user_id', $user->id)->delete();

            Auth::guard('api')->logout(true);

            Log::info('UserController-->logout_all, User logged out from all devices', [
                'user_id' => $user->id,
                'sessions_deleted' => $deleted_count
            ]);

            return response()->json([
                'message' => "Déconnecté de tous les appareils ($deleted_count sessions)"
            ], 200);

        } catch (\Exception $e) {
            Log::error('UserController-->logout_all, Logout all error', ['message' => $e->getMessage()]);

            return response()->json([
                'status' => 'error',
                'message' => 'Logout all failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }


    #[OA\Get(
        path: '/api/users/sessions',
        tags: ['User'],
        summary: "Liste des sessions actives de l'utilisateur",
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(response: 200, description: 'Sessions actives'),
            new OA\Response(response: 401, description: 'Non authentifié'),
        ]
    )]

    public function get_active_sessions()
    {
        $user = Auth::guard('api')->user();
        $current_jti = Auth::guard('api')->payload()->get('jti');

        $sessions = UserToken::where('user_id', $user->id)
            ->where('expires_at', '>', now())
            ->orderBy('last_used_at', 'desc')
            ->get()
            ->map(function($token) use ($current_jti) {
                return [
                    'jti' => $token->jti,
                    'device' => $this->parseUserAgent($token->user_agent),
                    'ip_address' => $token->ip_address,
                    'location' => $this->getApproximateLocation($token->ip_address),
                    'last_used' => $token->last_used_at->diffForHumans(),
                    'expires_at' => $token->expires_at->format('Y-m-d H:i:s'),
                    'is_current' => $token->jti === $current_jti,
                ];
            });

        return response()->json([
            'status' => 'success',
            'sessions' => $sessions
        ], 200);
    }



    private function parseUserAgent(?string $userAgent): string
    {
        if (!$userAgent) {
            return 'Appareil inconnu';
        }

        // Détection simple (ou utiliser une librairie comme mobiledetect)
        if (str_contains($userAgent, 'Mobile') || str_contains($userAgent, 'Android')) {
            return 'Mobile';
        } elseif (str_contains($userAgent, 'Tablet') || str_contains($userAgent, 'iPad')) {
            return 'Tablette';
        } else {
            return 'Ordinateur';
        }
    }


    private function getApproximateLocation(string $ip): string
    {
        // Version simple - ou utiliser une API comme ipinfo.io
        if ($ip === '127.0.0.1' || str_starts_with($ip, '192.168.')) {
            return 'Réseau local';
        }

        return 'Localisation inconnue';
    }


    #[OA\Delete(
        path: '/api/users/sessions/{jti}',
        tags: ['User'],
        summary: "Révoquer une session spécifique",
        security: [['bearerAuth' => []]],
        parameters: [
            new OA\Parameter(name: 'jti', in: 'path', required: true, schema: new OA\Schema(type: 'string'))
        ],
        responses: [
            new OA\Response(response: 200, description: 'Session révoquée'),
            new OA\Response(response: 401, description: 'Non authentifié'),
            new OA\Response(response: 404, description: 'Session non trouvée'),
        ]
    )]

    public function revoke_session(string $jti)
    {
        $user = Auth::guard('api')->user();
        $current_jti = Auth::guard('api')->payload()->get('jti');


        if ($jti === $current_jti) {
            return response()->json([
                'status' => 'error',
                'message' => 'Impossible de révoquer la session actuelle. Utilisez /logout.'
            ], 400);
        }

        $deleted = UserToken::where('user_id', $user->id)
            ->where('jti', $jti)
            ->delete();

        if (!$deleted) {
            return response()->json([
                'status' => 'error',
                'message' => 'Session non trouvée'
            ], 404);
        }

        Log::info('UserController->revoke_session, Session révoquée', [
            'user_id' => $user->id,
            'jti' => $jti
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'Session révoquée avec succès'
        ], 200);
    }
}
