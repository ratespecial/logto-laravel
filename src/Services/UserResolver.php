<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use RuntimeException;

/**
 * Turns validated Logto claims into a host-app user.  Shared by the API guard and the web sign-in flow.
 *
 * - Looks the user up by `logto.subject-column`, optionally claiming an unclaimed user by email.
 * - Persists claim-mapped attributes and dispatches {@see UserProvisionedEvent} for new rows.
 * - Never inserts a row for a subject without an email unless `logto.provision-without-email` is on.
 */
class UserResolver
{
    /**
     * @param  class-string<Authenticatable>  $userModel
     * @param  array<string, string>  $modelAttributes  Mapping of JWT claim name => user model attribute name.
     */
    public function __construct(
        private readonly string $userModel,
        private readonly array $modelAttributes = [],
    ) {}

    /**
     * Build a resolver for the model behind an `auth.providers.*` entry.
     */
    public static function forProvider(string $provider): self
    {
        $model = config("auth.providers.{$provider}.model");

        if (! is_string($model) || $model === '') {
            throw new RuntimeException("Auth provider [{$provider}] has no model configured");
        }

        return new self($model, config('logto.model-attributes', []));
    }

    /**
     * @param  array<string, mixed>  $claims  Must contain a non-empty `sub`.
     * @param  bool  $allowTransient  When the user would need an email to be stored but has none, return an unsaved
     *                                model instead of null.  Used for machine-to-machine tokens.
     * @return Authenticatable|null Null when the user can't be stored and $allowTransient is false.
     */
    public function resolve(array $claims, bool $allowTransient = false): ?Authenticatable
    {
        $subjectColumn = config('logto.subject-column');

        /** @var Model $model */
        $model = new $this->userModel();

        /** @var Authenticatable&Model $user */
        $user = $model->newQuery()
            ->firstOrNew([$subjectColumn => $claims['sub']]);

        if (! $user->exists && config('logto.link-unclaimed-by-email')) {
            $user = $this->findUnclaimedUser($model, $subjectColumn, $claims) ?? $user;
        }

        // forceFill so claim-mapped attributes are written even when the host
        // app's user model doesn't mark them fillable. The values come from a
        // validated token, not request input, so mass-assignment guarding is moot.
        $attributes                 = $this->mapClaimsToAttributes($claims);
        $attributes[$subjectColumn] = $claims['sub'];

        $user->forceFill($attributes);

        if (! $user->exists && $this->lacksRequiredEmail($claims) && ! config('logto.provision-without-email')) {
            if (! $allowTransient) {
                Log::debug("Logto subject {$claims['sub']} has no email; not provisioning");

                return null;
            }

            return $this->withScopes($user, $claims);
        }

        $user->save();

        $this->withScopes($user, $claims);

        if ($user->wasRecentlyCreated) {
            UserProvisionedEvent::dispatch($user);
        }

        return $user;
    }

    /**
     * Only enforced when the `email` claim is mapped to a user attribute; otherwise the host app doesn't store emails.
     *
     * @param  array<string, mixed>  $claims
     */
    protected function lacksRequiredEmail(array $claims): bool
    {
        return isset($this->modelAttributes['email']) && empty($claims['email']);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function withScopes(Authenticatable $user, array $claims): Authenticatable
    {
        if ($user instanceof OAuthScopable) {
            $user->setOAuthScopes((string) ($claims['scope'] ?? ''));
        }

        return $user;
    }

    /**
     * Find an existing user whose subject was cleared (e.g. after a Logto tenant migration)
     * and whose email matches the token's email claim, so it can be claimed by the new subject.
     *
     * @param  array<string, mixed>  $claims
     * @return (Authenticatable&Model)|null
     */
    protected function findUnclaimedUser(Model $model, string $subjectColumn, array $claims): ?Model
    {
        $emailColumn = $this->modelAttributes['email'] ?? null;
        if ($emailColumn === null || empty($claims['email'])) {
            return null;
        }

        /** @var (Authenticatable&Model)|null $user */
        $user = $model->newQuery()
            ->whereNull($subjectColumn)
            ->where($emailColumn, $claims['email'])
            ->first();

        if ($user !== null) {
            Log::info("Logto linked unclaimed user {$user->getKey()} to subject {$claims['sub']}");
        }

        return $user;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    protected function mapClaimsToAttributes(array $claims): array
    {
        $attributes = [];
        foreach ($this->modelAttributes as $claim => $field) {
            if (! empty($claims[$claim])) {
                $attributes[$field] = $claims[$claim];
            }
        }

        return $attributes;
    }
}
