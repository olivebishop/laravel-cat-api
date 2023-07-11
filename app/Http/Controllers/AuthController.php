<?php

    namespace App\Http\Controllers;

    use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
    use Illuminate\Foundation\Validation\ValidatesRequests;
    use Illuminate\Routing\Controller as BaseController;
    use Illuminate\Http\Request;
    use App\Models\User;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Validation\ValidationException;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Support\Facades\Auth;
    use Illuminate\Support\Facades\Log;

    class AuthController extends BaseController
    {
        use AuthorizesRequests, ValidatesRequests;

        public function signup(Request $request): JsonResponse
        {
            try {
                $validatedData = $request->validate([
                    'username' => 'required|min:3|max:10|unique:users,username',
                    'email' => 'required|email|unique:users,email',
                    'password' => 'required|min:6|regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/',
                ], [
                    'username.required' => 'Please enter a username.',
                    'username.min' => 'Username must be at least :min characters long.',
                    'username.max' => 'Username must not be more than :max characters long.',
                    'username.unique' => 'This username is already in use.',
                    'email.required' => 'Please enter an email address.',
                    'email.email' => 'Please enter a valid email address.',
                    'email.unique' => 'This email address is already in use.',
                    'password.required' => 'Please enter a password.',
                    'password.min' => 'Password must be at least :min characters long.',
                    'password.regex' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.',
                ]);

                $user = new User();
                $user->username = $validatedData['username'];
                $user->email = $validatedData['email'];
                $user->password = Hash::make($validatedData['password']);
                $user->save();

                return response()->json(['message' => 'Signup successful'], 200);
            } catch (ValidationException $e) {
                $errors = $e->validator->errors()->all();
                return response()->json(['errors' => $errors], 422);
            } catch (\Exception $e) {
                return response()->json(['error' => 'An error occurred while signing up. Please try again.'], 500);
            }
        }


        public function login(Request $request): JsonResponse
        {
            try {
                $validatedData = $request->validate([
                    'email' => 'required|email',
                    'password' => 'required',
                ], [
                    'email.required' => 'Please enter an email address.',
                    'email.email' => 'Please enter a valid email address.',
                    'password.required' => 'Please enter a password.',
                ]);

                $user = User::where('email', $validatedData['email'])->first();

                if (!$user || !Hash::check($validatedData['password'], $user->password)) {
                    return response()->json(['error' => 'Invalid credentials.'], 401);
                }

                $is_admin = $user->hasRole('admin');
                $token = $user->createToken('auth-token')->plainTextToken;

                return response()->json(['token' => $token, 'user' => $user, 'is_admin' => $is_admin], 200);

            } catch (ValidationException $e) {
                $errors = $e->validator->errors()->all();
                return response()->json(['errors' => $errors], 422);
            } catch (\Exception $e) {
                $errorMessage = $e->getMessage(); // Get the specific error message
                Log::error($errorMessage); // Log the error message for debugging purposes

                return response()->json(['error' => $errorMessage], 500);
            }
        }

        public function logout(): JsonResponse
        {
            try {
                $user = Auth::user();
                if ($user) {
                    $user->tokens()->delete();
                    return response()->json(['message' => 'You have logged out.'], 200);
                }
            } catch (\Exception $e) {
                $errorMessage = $e->getMessage(); // Get the specific error message
                Log::error($errorMessage); // Log the error message for debugging purposes

                return response()->json(['error' => $errorMessage], 500);
            }
        }
    }
