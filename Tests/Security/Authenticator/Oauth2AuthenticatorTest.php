<?php

namespace Security\Authenticator;

use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Security\Authenticator\Oauth2Authenticator;
use FOS\OAuthServerBundle\Tests\Functional\TestBundle\Entity\AccessToken;
use FOS\OAuthServerBundle\Tests\Storage\OAuthStorageTest\User;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use OAuth2\OAuth2;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Test class for Oauth2Authenticator
 */
class Oauth2AuthenticatorTest extends TestCase
{
    protected Oauth2Authenticator $authenticator;

    protected OAuth2|MockObject $serverService;


    protected UserCheckerInterface|MockObject $user;

    protected AccessToken|MockObject $accessToken;

    protected $userChecker;

    protected function setUp(): void
    {
        $this->serverService = $this->getMockBuilder(OAuth2::class)
            ->disableOriginalConstructor()
            ->getMock();
            
        $this->userChecker = $this->getMockBuilder(UserCheckerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->authenticator = new Oauth2Authenticator($this->serverService, $this->userChecker);

        $this->accessToken = $this->createMock( AccessToken::class );
        $client = $this->createMock( ClientInterface::class );
        $this->accessToken->method('getClient')->willReturn( $client );
    }

    public function testSupportsWithToken(): void
    {
        $request = new Request();

        $this->serverService->method('getBearerToken')->willReturn('token');

        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsWithoutToken(): void
    {
        $request = new Request();

        $this->serverService->method('getBearerToken')->willReturn(null);

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testAuthenticateMissingToken(): void
    {
        $request = new Request();

        $this->serverService->method('verifyAccessToken')->willReturn(null);
        $this->expectException(AuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticate(): void
    {
        $request = new Request();

        $this->serverService->method('verifyAccessToken')->willReturn($this->accessToken);
        $this->serverService->method('getBearerToken')->willReturn($this->accessToken);

        $actual = $this->authenticator->authenticate($request);

        $this->assertInstanceOf(SelfValidatingPassport::class, $actual);
    }
}