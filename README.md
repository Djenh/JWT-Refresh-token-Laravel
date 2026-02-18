
## Install a secure JWT authentication system for Laravel REST API app
Here is a step-by-step guide to secure authentication using JWT for Laravel



### **Step 1 : Install JWT**

Link : [https://github.com/PHP-Open-Source-Saver/jwt-auth](https://github.com/PHP-Open-Source-Saver/jwt-auth)

Execute the command
``` php
composer require php-open-source-saver/jwt-auth
```

``` php
php artisan vendor:publish --provider="PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider"
```

Now, generate secret key for JWT
``` php
php artisan jwt:secret
```

In  **`App\Models\User.php`** file, add this

``` console
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
```

and add implementation of JWTSubject to User class **`implements JWTSubject`**

Then complete the User class with the two followin method

``` console

public function getJWTIdentifier()
{
    return $this->getKey();
}


public function getJWTCustomClaims()
{
    return [];
}
```

In  the file `app\config\auth.php`, add this in authentication guards key.

``` console

'guards' => [
    'api' => [
        'driver' => 'jwt', // Or 'jwt' if using JWT, or 'passport' if using Passport, or 'sanctum' if using Laravel Sanctum
        'provider' => 'users',
    ],
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],    
],
```

To get the logged in user, use the following syntax
``` php
$user = Auth::guard('api')->user();
```


### **Step 2 : Configure JWT with expiration**

Open the file `config/jwt.php` and edit it as follow

```php

    'ttl' => env('JWT_TTL', 60), // 60 minutes
    
    'refresh_ttl' => env('JWT_REFRESH_TTL', 20160), // 14 days
    
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),
    
    // Add it if not exists
    'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 30),

```

Then edit `.env` file by adding these lines

```console
    JWT_SECRET=Pxxxxxx
    JWT_ALGO=HS256
    JWT_TTL=60
    JWT_REFRESH_TTL=20160
    JWT_BLACKLIST_ENABLED=true
    JWT_BLACKLIST_GRACE_PERIOD=30
```

### **Step 3 : Create user_tokens migration**

Run the command 
```console
    php artisan make:model UserToken -m
```

In the migration file `database/migrations/XXXX_XX_XX_create_user_tokens_table.php` created for ***user_tokens** add the following content

```php

    public function up(): void
    {
        Schema::create('user_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            $table->string('jti', 64)->unique()->comment('JWT ID unique');
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('last_used_at');
            $table->timestamp('expires_at');
            $table->timestamps();
            
            // Index to optimize requests
            $table->index('jti');
            $table->index('expires_at');            
        });
    }

```

Then execute the command 
```console
    php artisan migrate
```

In the model file `app/Models/UserToken.php`, add the following content

```php

    use Illuminate\Database\Eloquent\Relations\BelongsTo;

    class UserToken extends Model
    {
        use HasFactory;

        protected $fillable = [
            'user_id',
            'jti',
            'ip_address',
            'user_agent',
            'last_used_at',
            'expires_at',
        ];

        protected $casts = [
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
        ];

        
        public function user(): BelongsTo
        {
            return $this->belongsTo(User::class);
        }
        
        public function isExpired(): bool
        {
            return $this->expires_at < now();
        }
        
        public function scopeActive($query)
        {
            return $query->where('expires_at', '>', now());
        }
    }

```

### **Step 4 : Create middlewares JwtSecurityMiddleware and JwtRefreshMiddleware**

Execute the command 
```console
    php artisan make:middleware JwtSecurityMiddleware

    php artisan make:middleware JwtRefreshMiddleware
```

Edit the middleware file `app/Http/Middleware/JwtSecurityMiddleware.php`


```php

    namespace App\Http\Middleware;

    use Closure;
    use Illuminate\Http\Request;
    use Symfony\Component\HttpFoundation\Response;
    use App\Models\UserToken;
    use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
    use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
    use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
    use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
    use Illuminate\Support\Facades\Log;

    class JwtSecurityMiddleware
    {
        /**
         * Handle an incoming request.
         */
        public function handle(Request $request, Closure $next): Response
        {
            try {
                // Get the payload of token
                $payload = JWTAuth::parseToken()->getPayload();
                $jti = $payload->get('jti');
                $user_id = $payload->get('sub');
                
                // Check if token exists in DB
                $token_record = UserToken::where('jti', $jti)
                    ->where('user_id', $user_id)
                    ->first();
                
                if (!$token_record) {
                    return response()->json([
                        'status' => 'error',
                        'message' => 'Token unauthorized'
                    ], 401);
                }
                
                // Check expiration datetime
                if ($token_record->isExpired()) {
                    $token_record->delete();
                    return response()->json([
                        'status' => 'error',
                        'message' => 'Session expired'
                    ], 401);
                }
                
                // Check IP address
                if ($token_record->ip_address !== $request->ip()) {
                    Log::warning('IP mismatch', [
                        'user_id' => $user_id,
                        'jti' => $jti,
                        'expected_ip' => $token_record->ip_address,
                        'actual_ip' => $request->ip(),
                        'user_agent' => $request->userAgent()
                    ]);
                    
                    // Strict option to block request
                    // return response()->json([
                    //     'status' => 'error',
                    //     'message' => 'Suspecious IP address detected'
                    // ], 403);
                }
                
                // Update datetime last_used_at
                $token_record->update(['last_used_at' => now()]);
                
            } catch (TokenExpiredException $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token expired'
                ], 401);
            } catch (TokenInvalidException $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token invalide'
                ], 401);
            } catch (JWTException $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token missed'
                ], 401);
            } catch (\Exception $e) {
                Log::error('JwtSecurityMiddleware error', [
                    'message' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ]);
                return response()->json([
                    'status' => 'error',
                    'message' => 'Authentication error'
                ], 401);
            }
            
            return $next($request);
        }
    }

```

Check the file in this repository to get the full content of `app/Http/Middleware/JwtRefreshMiddleware.php`.


Now we need to register the middleware, so the Laravel app will be aware of it 
and we can use it in routes and controllers.

Open the file `bootstrap/app.php`

```php
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'jwt.security' => \App\Http\Middleware\JwtSecurityMiddleware::class,
            'jwt.refresh' => \App\Http\Middleware\JwtRefreshMiddleware::class,
        ]);
    })
```


### **Step 5 : Edit AuthController**

To get the full source code of AuthController and UserController, check the attached files of this repository.

After creating authentication methods, now apply middlewares to routes. 
In file `route/api.php`

```php
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [UserController::class, 'register']);

Route::post('/refresh', [UserController::class, 'refresh'])->middleware('jwt.refresh');

// Routes protégées avec JWT + Middleware de sécurité
Route::middleware(['auth:api', 'jwt.security'])->group(function () {
    
    Route::get('/users', [UserController::class, 'index']);
    Route::get('/profile', [UserController::class, 'get_profile']);
    
});

```

To see all routes, see files of this repository.


### **Step 6 : Clean expired tokens**

Create a command to clean expired tokens.
Execute the command

```console
php artisan make:command CleanExpiredTokens
```

Go into file `app/Console/Commands/CleanExpiredTokens.php`

```php
    use App\Models\UserToken;
    use Illuminate\Support\Facades\Log;

    class CleanExpiredTokens extends Command
    {
        protected $signature = 'tokens:clean {--days=7 : Number of days of retention}';
        protected $description = 'Delete expired tokens from database';

        public function handle()
        {
            $days = (int) $this->option('days');
            $cutoffDate = now()->subDays($days);
            
            $deleted = UserToken::where('expires_at', '<', $cutoffDate)->delete();
            
            $this->info("✓ $deleted tokens expired deleted (more than $days days)");
            
            Log::info('Expired tokens cleaned', [
                'deleted_count' => $deleted,
                'cutoff_date' => $cutoffDate
            ]);
            
            return Command::SUCCESS;
        }
    }

```

Plan execution of th cleaning command
Go in the file `routes/console.php` and add the following

```php
    use Illuminate\Support\Facades\Schedule;

    Schedule::command('tokens:clean')->dailyAt('02:00');
```

Now test the command by running

```console
    php artisan tokens:clean

    # or if you want to choose specific duration
    php artisan tokens:clean --days=14
```

### **Step 7 : Verify CORS configs**

Publish CORS configurations by running the command

```console
    php artisan config:publish cors
```

Or the command 
```console
    php artisan vendor:publish --tag=cors
```

Then you'll have a new file created `config/cors.php`
Open it and set right parameters you like or leave default parameters.

Here is an example of parameters you can set

```php
    return [
        'paths' => ['api/*', 'sanctum/csrf-cookie'],

        'allowed_methods' => ['*'],

        'allowed_origins' => [
            'http://localhost:3000',  // Frontend local
            'http://localhost:8080',  // Frontend local
            'https://my-domaine.com', // Production
        ],

        'allowed_origins_patterns' => [],

        'allowed_headers' => [
            'Content-Type',
            'X-Requested-With',
            'Authorization',
            'Accept',
            'Origin',
        ],

        'exposed_headers' => [
            'Authorization',
        ],

        'max_age' => 86400, // 24 hours

        'supports_credentials' => true,
    ];

```


Open the file `bootstrap/app.php` and check if CORS is activated

```php
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->api(prepend: [
            \Illuminate\Http\Middleware\HandleCors::class,
        ]);
    })
```



### **Step 8 : Launch the app**

Now clean everything and launch the app

```console
    php artisan config:clear
    php artisan cache:clear
    php artisan route:clear
    php artisan view:clear
    php artisan serve
```

You can test your endpoints.
