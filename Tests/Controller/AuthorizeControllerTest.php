<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Tests\Controller;

use FOS\OAuthServerBundle\Controller\AuthorizeController;
use FOS\OAuthServerBundle\Event\OAuthEvent;
use FOS\OAuthServerBundle\Form\Handler\AuthorizeFormHandler;
use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;
use OAuth2\OAuth2;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Form\Form;
use Symfony\Component\Form\FormView;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;
use function random_bytes;

class AuthorizeControllerTest extends TestCase
{
    protected RequestStack|MockObject $requestStack;
    protected SessionInterface|MockObject $session;
    protected Form|MockObject $form;
    protected AuthorizeFormHandler|MockObject $authorizeFormHandler;
    protected OAuth2|MockObject $oAuth2Server;
    protected Environment|MockObject $twig;
    protected TokenStorageInterface|MockObject $tokenStorage;
    protected UrlGeneratorInterface|MockObject $router;
    protected ClientManagerInterface|MockObject $clientManager;
    protected EventDispatcherInterface|MockObject $eventDispatcher;
    protected AuthorizeController $instance;
    protected Request|MockObject $request;
    protected ParameterBag|MockObject $requestQuery;
    protected ParameterBag|MockObject $requestRequest;
    protected UserInterface|MockObject $user;
    protected ClientInterface|MockObject $client;
    protected OAuthEvent|MockObject $event;
    protected FormView|MockObject $formView;

    public function setUp(): void
    {
        $this->requestStack = $this->getMockBuilder(RequestStack::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->form = $this->getMockBuilder(Form::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->authorizeFormHandler = $this->getMockBuilder(AuthorizeFormHandler::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->oAuth2Server = $this->getMockBuilder(OAuth2::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->twig = $this->getMockBuilder(Environment::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->tokenStorage = $this->getMockBuilder(TokenStorageInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->router = $this->getMockBuilder(UrlGeneratorInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->clientManager = $this->getMockBuilder(ClientManagerInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->eventDispatcher = $this->getMockBuilder(EventDispatcherInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->session = $this->getMockBuilder(SessionInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->instance = new AuthorizeController(
            $this->requestStack,
            $this->form,
            $this->authorizeFormHandler,
            $this->oAuth2Server,
            $this->twig,
            $this->tokenStorage,
            $this->router,
            $this->clientManager,
            $this->eventDispatcher
        );

        $this->request = $this->getMockBuilder(Request::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->requestQuery = $this->getMockBuilder(ParameterBag::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->requestRequest = $this->getMockBuilder(ParameterBag::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->user = $this->getMockBuilder(UserInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->client = $this->getMockBuilder(ClientInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->event = $this->getMockBuilder(OAuthEvent::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->formView = $this->getMockBuilder(FormView::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        parent::setUp();
    }

    public function testAuthorizeActionWillThrowAccessDeniedException(): void
    {
        $token = $this->getMockBuilder(TokenInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->tokenStorage
            ->expects($this->any())
            ->method('getToken')
            ->willReturn($token)
        ;

        $token
            ->expects($this->any())
            ->method('getUser')
            ->willReturn(null)
        ;

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('This user does not have access to this section.');

        $this->instance->authorizeAction($this->request);
    }

    public function testAuthorizeActionWillRenderTemplate(): void
    {
        $token = $this->getMockBuilder(TokenInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->tokenStorage
            ->expects($this->exactly(1))
            ->method('getToken')
            ->willReturn($token)
        ;

        $token
            ->expects($this->exactly(1))
            ->method('getUser')
            ->willReturn($this->user)
        ;

        $this->request
                ->expects($this->any())
                ->method('getSession')
                ->willReturn($this->session)
        ;

        $this->session
            ->expects($this->exactly(1))
            ->method('get')
            ->with('_fos_oauth_server.ensure_logout')
            ->willReturn(false)
        ;

        $propertyReflection = new ReflectionProperty(AuthorizeController::class, 'client');
        $propertyReflection->setAccessible(true);
        $propertyReflection->setValue($this->instance, $this->client);

        $this->eventDispatcher
            ->expects($this->exactly(1))
            ->method('dispatch')
            ->with(new OAuthEvent($this->user, $this->client), OAuthEvent::PRE_AUTHORIZATION_PROCESS)
            ->willReturn($this->event)
        ;

        $this->event
            ->expects($this->exactly(1))
            ->method('isAuthorizedClient')
            ->with()
            ->willReturn(false)
        ;

        $this->authorizeFormHandler
            ->expects($this->exactly(1))
            ->method('process')
            ->with()
            ->willReturn(false)
        ;

        $this->form
            ->expects($this->exactly(1))
            ->method('createView')
            ->willReturn($this->formView)
        ;

        $this->twig
            ->expects($this->exactly(1))
            ->method('render')
            ->with(
                '@FOSOAuthServer/Authorize/authorize.html.twig',
                [
                    'form' => $this->formView,
                    'client' => $this->client,
                ]
            )
            ->willReturn("")
        ;

        $response = new Response();
        $this->assertEquals($response, $this->instance->authorizeAction($this->request));
    }

    public function testAuthorizeActionWillFinishClientAuthorization(): void
    {
        $token = $this->getMockBuilder(TokenInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->tokenStorage
            ->expects($this->any())
            ->method('getToken')
            ->willReturn($token)
        ;

        $token
            ->expects($this->any())
            ->method('getUser')
            ->willReturn($this->user)
        ;

        $this->request
                ->expects($this->any())
                ->method('getSession')
                ->willReturn($this->session)
        ;

        $this->session
            ->expects($this->any())
            ->method('get')
            ->with('_fos_oauth_server.ensure_logout')
            ->willReturn(false)
        ;

        $propertyReflection = new ReflectionProperty(AuthorizeController::class, 'client');
        $propertyReflection->setAccessible(true);
        $propertyReflection->setValue($this->instance, $this->client);

        $this->eventDispatcher
            ->expects($this->any())
            ->method('dispatch')
            ->with(new OAuthEvent($this->user, $this->client), OAuthEvent::PRE_AUTHORIZATION_PROCESS)
            ->willReturn($this->event)
        ;

        $this->event
            ->expects($this->any())
            ->method('isAuthorizedClient')
            ->with()
            ->willReturn(true)
        ;

        $randomScope = 'scope' . random_bytes(10);

        $this->request
            ->expects($this->any())
            ->method('get')
            ->with('scope', null)
            ->willReturn($randomScope)
        ;

        $response = new Response();

        $this->oAuth2Server
            ->expects($this->any())
            ->method('finishClientAuthorization')
            ->with(
                true,
                $this->user,
                $this->request,
                $randomScope
            )
            ->willReturn($response)
        ;

        $this->assertSame($response, $this->instance->authorizeAction($this->request));
    }

    public function testAuthorizeActionWillEnsureLogout(): void
    {
        $token = $this->getMockBuilder(TokenInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->tokenStorage
            ->expects($this->exactly(1))
            ->method('getToken')
            ->willReturn($token)
        ;

        $token
            ->expects($this->exactly(1))
            ->method('getUser')
            ->willReturn($this->user)
        ;

        $this->request
            ->expects($this->any())
            ->method('getSession')
            ->willReturn($this->session)
        ;

        $this->session
            ->expects($this->exactly(1))
            ->method('get')
            ->with('_fos_oauth_server.ensure_logout')
            ->willReturn(true)
        ;

        $this->session
            ->expects($this->exactly(1))
            ->method('invalidate')
            ->with(600)
            ->willReturn(true)
        ;

        $this->session
            ->expects($this->exactly(1))
            ->method('set')
            ->with('_fos_oauth_server.ensure_logout', true)
        ;

        $propertyReflection = new ReflectionProperty(AuthorizeController::class, 'client');
        $propertyReflection->setAccessible(true);
        $propertyReflection->setValue($this->instance, $this->client);

        $this->eventDispatcher
            ->expects($this->exactly(1))
            ->method('dispatch')
            ->with(new OAuthEvent($this->user, $this->client), OAuthEvent::PRE_AUTHORIZATION_PROCESS)
            ->willReturn($this->event)
        ;

        $this->event
            ->expects($this->exactly(1))
            ->method('isAuthorizedClient')
            ->with()
            ->willReturn(false)
        ;

        $this->authorizeFormHandler
            ->expects($this->exactly(1))
            ->method('process')
            ->with()
            ->willReturn(false)
        ;

        $this->form
            ->expects($this->exactly(1))
            ->method('createView')
            ->willReturn($this->formView)
        ;

        $response = new Response();

        $this->twig
            ->expects($this->exactly(1))
            ->method('render')
            ->with(
                '@FOSOAuthServer/Authorize/authorize.html.twig',
                [
                    'form' => $this->formView,
                    'client' => $this->client,
                ]
            )
            ->willReturn("")
        ;

        $this->assertEquals($response, $this->instance->authorizeAction($this->request));
    }

    /**
     * @TODO Rewrite this test since Request::$query and Request::$request are now typed with final classes
     *       Than can't be mocked anymore
     */
    public function testAuthorizeActionWillProcessAuthorizationForm(): void
    {
        $token = $this->getMockBuilder(TokenInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->tokenStorage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($token)
        ;

        $token
            ->expects($this->once())
            ->method('getUser')
            ->willReturn($this->user)
        ;

        $this->request
                ->expects($this->any())
                ->method('getSession')
                ->willReturn($this->session)
        ;

        $this->session
            ->method('get')
            ->with('_fos_oauth_server.ensure_logout')
            ->willReturn(true)
        ;

        $propertyReflection = new ReflectionProperty(AuthorizeController::class, 'client');
        $propertyReflection->setAccessible(true);
        $propertyReflection->setValue($this->instance, $this->client);


        $this->eventDispatcher
            ->expects($this->exactly(2))
            ->method('dispatch')
            ->withConsecutive(
                [ new OAuthEvent($this->user, $this->client), OAuthEvent::PRE_AUTHORIZATION_PROCESS ],
                [ new OAuthEvent($this->user, $this->client, true), OAuthEvent::POST_AUTHORIZATION_PROCESS ]
            )
            ->willReturn($this->event)
        ;

        $this->event
            ->expects($this->once())
            ->method('isAuthorizedClient')
            ->willReturn(false)
        ;

        $this->authorizeFormHandler
            ->expects($this->once())
            ->method('process')
            ->willReturn(true)
        ;

        $this->authorizeFormHandler
            ->expects($this->any())
            ->method('isAccepted')
            ->willReturn(true)
        ;

        $formName = 'formName'. random_bytes(10);

        $this->form
            ->expects($this->once())
            ->method('getName')
            ->willReturn($formName)
        ;

        $this->requestQuery
            ->expects($this->once())
            ->method('all')
            ->willReturn([])
        ;

        $this->requestRequest
            ->expects($this->once())
            ->method('has')
            ->with($formName)
            ->willReturn(true)
        ;

        $randomScope = 'scope'. random_bytes(10);

        $this->authorizeFormHandler
            ->expects($this->once())
            ->method('getScope')
            ->willReturn($randomScope)
        ;

        $response = new Response();

        $this->oAuth2Server
            ->expects($this->once())
            ->method('finishClientAuthorization')
            ->with(
                true,
                $this->user,
                $this->request,
                $randomScope
            )
            ->willReturn($response)
        ;

        $this->assertSame($response, $this->instance->authorizeAction($this->request));
    }
}
